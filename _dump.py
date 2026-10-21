import fitz, os, sys
d = r'd:\大四上\软件开发综合实验'
out = os.path.join(d, '_txt')
for f in sys.argv[1:]:
    p = os.path.join(d, f)
    doc = fitz.open(p)
    txt = []
    for i, pg in enumerate(doc):
        txt.append('=== PAGE %d ===' % (i+1))
        txt.append(pg.get_text())
    open(os.path.join(out, f + '.txt'), 'w', encoding='utf-8').write('\n'.join(txt))
    print(f, doc.page_count)
