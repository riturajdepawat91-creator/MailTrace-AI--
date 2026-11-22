# Microsoft Graph Permission Matrix

> **Superseded for SIH mailbox access.** Gmail API is the selected provider. Do not create this Graph permission set for the Gmail flow. See [GMAIL_API_SETUP.md](GMAIL_API_SETUP.md) and [GMAIL_SYNC_DESIGN.md](GMAIL_SYNC_DESIGN.md).

Target: one signed-in SIH mailbox, read-only scanning, and user-authorized login. Permissions below are for Microsoft Graph v1.0 and current Microsoft documentation as checked on 2026-11-20.

| Capability | Graph endpoint | Proposed scope | Notes |
|---|---|---|---|
| Current signed-in user | `GET /me?$select=id,displayName,userPrincipalName,mail` | Delegated `User.Read` | `/me` requires a signed-in user and delegated permission. Do not use directory-wide user scopes. |
| Root mail folders | `GET /me/mailFolders`; well-known Inbox `GET /me/mailFolders/inbox` | `Mail.Read` for the complete scan app | Folder listing's least-privileged option is `Mail.ReadBasic`, but full app requires body/attachment access and notification support. Root listing does not recursively return all nested folders. |
| Inbox messages | `GET /me/mailFolders/inbox/messages?$select=id,subject,from,receivedDateTime,internetMessageId,hasAttachments` | `Mail.Read` | Use `$top`/paging; delta should be preferred for ongoing sync. Avoid retrieving body for every historical message. |
| Message details/body | `GET /me/messages/{id}?$select=...` with `Prefer: outlook.body-content-type="text"` | `Mail.Read` | `Mail.ReadBasic` excludes body/bodyPreview and attachments. Fetch full body only for newly detected messages and analyze in memory for SAFE/LOW. |
| Raw MIME message | `GET /me/messages/{id}/$value` | `Mail.Read` | Returns MIME content suitable for existing EML parser. Bound size in the client and do not persist SAFE/LOW raw content. |
| Internet headers | `GET /me/messages/{id}?$select=internetMessageHeaders` | `Mail.Read` | Graph message example uses `$select=internetMessageHeaders`; preserve repeated header values when mapping to parser input. |
| Attachment metadata/list | `GET /me/messages/{id}/attachments` | Delegated `Mail.Read` | List attachments and their type/name/size. `Mail.ReadBasic` does not include attachments. |
| Attachment bytes | `GET /me/messages/{id}/attachments/{attachment-id}/$value` or retrieve a fileAttachment's `contentBytes` as applicable | `Mail.Read` | Only fetch bytes when attachment scanning is required; apply size/count/time limits. Treat itemAttachment/referenceAttachment separately. |
| Message delta | `GET /me/mailFolders/{folder-id}/messages/delta` | `Mail.Read` for full SIH scan; Graph's least privileged delta scope can be `Mail.ReadBasic` | Maintain the exact `@odata.nextLink` until final `@odata.deltaLink`; persist the opaque delta link as sync state, not email content. Start with Inbox. |
| Mail-folder delta (optional) | `GET /me/mailFolders/delta` | Delegated mail read permission | Useful only if tracking folder changes; not required for a fixed Inbox demo. |
| Change notifications | `POST /subscriptions` for resource `/me/mailFolders('inbox')/messages` with `changeType: created` | Delegated `Mail.Read` | Graph requires a read scope for message subscriptions; delegated subscription is limited to signed-in user's own mailbox. Notification is a wake-up hint; fetch the message/delta to reconcile. |

Microsoft Graph sources: [Get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0), [list folders](https://learn.microsoft.com/en-us/graph/api/user-list-mailfolders?view=graph-rest-1.0), [list messages](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messages?view=graph-rest-1.0), [get message and internet headers](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0), [list attachments](https://learn.microsoft.com/en-us/graph/api/message-list-attachments?view=graph-rest-1.0), [message delta](https://learn.microsoft.com/en-us/graph/api/message-delta?view=graph-rest-1.0), [create subscription](https://learn.microsoft.com/en-us/graph/api/subscription-post-subscriptions?view=graph-rest-1.0), [permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference).

## Permission choice

**Requested delegated Graph permissions:** `User.Read` + `Mail.Read`. `Mail.ReadBasic` alone is insufficient because the SIH analysis needs body and attachment access; Microsoft also documents `Mail.Read` for Outlook message change subscriptions. `offline_access` is an OAuth scope for renewable signed-in access, not a Graph resource permission; Microsoft notes delegated grants implicitly provide it in supported flows, while MSAL manages token renewal from its cache.

**Not requested:** application permissions, `Mail.ReadWrite`, `Mail.ReadWrite.Shared`, `Mail.Send`, delete/write scopes, shared-mail access, directory-wide user permissions. Do not request mailbox write/delete access for quarantine. The current SIH privacy design calls for local evidence preservation and SOC transfer; a future approved mailbox move/delete action would require a separate design and permission review.

## Change notifications versus local endpoints

Microsoft Graph webhook delivery requires a publicly reachable HTTPS notification URL with validation and quick responses. A Windows laptop's `localhost` listener is not reachable by Graph. For the prototype, use Inbox delta synchronization as the dependable local polling/reconciliation path. Add Graph change notifications only if an approved HTTPS relay or controlled development tunnel is available; avoid sending message resource data in notifications. Implement subscription renewal/lifecycle recovery and run delta after every notification to cover missed events. Outlook message subscriptions have a maximum lifetime listed by Microsoft as 10,080 minutes for ordinary notifications (less than seven days); rich notifications have shorter limits. Recheck the Graph documentation when implementing.

Source: [webhook delivery requirements](https://learn.microsoft.com/en-us/graph/change-notifications-delivery-webhooks), [Outlook change notifications](https://learn.microsoft.com/en-us/graph/outlook-change-notifications-overview), [subscription lifetimes](https://learn.microsoft.com/en-us/graph/change-notifications-overview).

