from pathlib import Path
import urllib.request, tarfile, hashlib, json, random, shutil
ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'data'/'public_email_corpus'; RAW=DATA/'raw'; PREP=DATA/'prepared'; SEED=20261016
SOURCES={'ham':('https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2','SpamAssassin easy_ham public corpus'),'spam':('https://spamassassin.apache.org/old/publiccorpus/20030228_spam_2.tar.bz2','SpamAssassin spam_2 public corpus')}
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): h.update(b)
 return h.hexdigest()
def extract(archive,target):
 target.mkdir(parents=True,exist_ok=True)
 with tarfile.open(archive,'r:bz2') as tf:
  for m in tf.getmembers():
   if not m.isfile(): continue
   name=Path(m.name).name
   if not name or name in {'.','..','README','index'}: continue
   src=tf.extractfile(m)
   if src is None: continue
   raw=src.read()
   if not raw or b'\n' not in raw or b':' not in raw.split(b'\n',1)[0]: continue
   out=target/(name+'.eml')
   if not out.exists(): out.write_bytes(raw)
def main():
 RAW.mkdir(parents=True,exist_ok=True); sources={}; counts={}
 for label,(url,title) in SOURCES.items():
  archive=RAW/url.rsplit('/',1)[-1]
  if not archive.exists():
   print('DOWNLOAD',url)
   req=urllib.request.Request(url,headers={'User-Agent':'MailTrace-AI provisional dataset preparation/1.0'})
   with urllib.request.urlopen(req,timeout=45) as resp,archive.open('wb') as out: shutil.copyfileobj(resp,out)
  folder=RAW/label
  if not list(folder.glob('*.eml')): extract(archive,folder)
  files=sorted(folder.glob('*.eml')); counts[label]=len(files)
  sources[label]={'url':url,'title':title,'archive_sha256':sha(archive),'files':files}
  print(f'CORPUS {label}: {len(files)} messages; archive_sha256={sources[label]["archive_sha256"]}')
 n=min(100,min(counts.values()))
 if n<1: raise SystemExit('No parseable emails downloaded')
 rng=random.Random(SEED); splits={'train':[],'dev':[],'holdout':[]}
 for label,source in sources.items():
  items=list(source['files']); rng.shuffle(items); hold=items[:n]; rest=items[n:]; nd=max(1,int(len(rest)*.20)) if len(rest)>1 else 0
  for split,part in [('holdout',hold),('dev',rest[:nd]),('train',rest[nd:])]:
   for path in part:
    splits[split].append({'fixture_id':f'PSA-{split.upper()}-{label.upper()}-{sha(path)[:12]}','split':split,'email_path':str(path.relative_to(ROOT.parent)).replace('\\','/'),'sha256':sha(path),'expected_label':label,'label_quality':'PROVISIONAL: dataset-curator labelled, not human-reviewed by project team','independent_review_status':'not_human_reviewed','provenance':source['title'],'source_url':source['url'],'model_version':None,'policy_version':None})
 PREP.mkdir(parents=True,exist_ok=True)
 for split,rows in splits.items():
  rows.sort(key=lambda x:x['fixture_id']); (PREP/f'{split}.jsonl').write_text(''.join(json.dumps(x,sort_keys=True)+'\n' for x in rows),encoding='utf-8')
 holdsha=sha(PREP/'holdout.jsonl'); (PREP/'holdout.sha256').write_text(f'{holdsha}  holdout.jsonl\n',encoding='ascii')
 report={'schema_version':'1.0','seed':SEED,'label_quality':'PROVISIONAL: dataset-curator labelled, not human-reviewed by project team','raw_data_path':str(RAW.relative_to(ROOT.parent)).replace('\\','/'),'prepared_path':str(PREP.relative_to(ROOT.parent)).replace('\\','/'),'holdout_frozen':True,'holdout_manifest_sha256':holdsha,'source_distribution':{},'class_balance':{},'split_sizes':{},'sources':{k:{'title':v['title'],'url':v['url'],'archive_sha256':v['archive_sha256'],'messages':counts[k]} for k,v in sources.items()},'license_note':'No single explicit corpus-wide license was identified at the linked archive during preparation. Individual messages may be copyrighted; internal evaluation only, do not redistribute raw messages, and seek legal review before external redistribution.'}
 for split,rows in splits.items():
  report['split_sizes'][split]=len(rows); report['class_balance'][split]={k:sum(1 for x in rows if x['expected_label']==k) for k in SOURCES}; report['source_distribution'][split]={'SpamAssassin public corpus':len(rows)}
 (PREP/'dataset_report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print('SPLIT_SIZES',json.dumps(report['split_sizes'],sort_keys=True)); print('CLASS_BALANCE',json.dumps(report['class_balance'],sort_keys=True)); print('SOURCE_DISTRIBUTION',json.dumps(report['source_distribution'],sort_keys=True)); print('HOLDOUT_SHA256',holdsha)
if __name__=='__main__': main()
