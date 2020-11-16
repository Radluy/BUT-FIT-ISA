# Filtrující DNS resolver

Program, ktorý prijíma dns dotazy a následne ich filtruje podľa blacklistu.
Podporovaný je iba typ DNS dotazu A a  UDP protokol na transportnej vrstve.

## Použitie: 
dns -s server [-p port] -f filter_file [-v]  
    -s: ipv4/ipv6 adresa alebo doménové meno DNS servera kam sa dotaz prepošle.  
    -p: port na ktorom bude server počúvať. Ak nie je špecifikovaný tak sa použije port 53. 
    -f: názov súboru ktorý obsahuje nežiadúce domény. Ak daný súbor neexistuje, všetky dotazy sa budú preposielať bez filtrovania. 
    -v: príznak na výrečnosť programu. Server bude oznamovať na výstup akú činnosť vykonáva.  

## Príklad spustenia: 
    ./dns -s 8.8.8.8 -f filterfile2.txt -p 1234
alebo  
    make example


