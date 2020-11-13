# Filtrující DNS resolver

Program, ktorý prijíma dns dotazy a následne ich filtruje podľa blacklistu.
Podporovaný je iba typ DNS dotazu A a  UDP protokol na transportnej vrstve.

Použitie: dns -s server [-p port] -f filter_file [-v]
    -s: IP adresa nebo doménové jméno DNS serveru (resolveru), kam se má zaslat dotaz.
    -p port: Číslo portu, na kterém bude program očekávat dotazy. Výchozí je port 53.
    -f filter_file: Jméno souboru obsahující nežádoucí domény.
    -v program bude vypisovať dodatočné informácie o priebehu.

Príklad spustenia: 
    ./dns -s 8.8.8.8 -f filterfile.txt -p 5353
alebo
    make example


