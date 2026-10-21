import re,io,sys
sys.stdout.reconfigure(encoding='utf-8')
for name in ['5.pdf','4.pdf','3.pdf','1.pdf','2.pdf','6.pdf','7.压缩解压及其关键技术.pdf']:
    t = open(r'd:\大四上\软件开发综合实验\_txt'+chr(92)+name+'.txt', encoding='utf-8').read()
    pages = t.split('=== PAGE ')
    print('#####', name)
    for pg in pages[1:]:
        head = [l for l in pg.split(chr(10))[1:6] if l.strip()][:2]
        print(pg.split(chr(10))[0].strip().rstrip(' ='), '|', ' / '.join(x.strip() for x in head))
