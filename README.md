# IPK PAKET SNIFFER
### AUTHOR: Maroš Geffert

Program zachýtáva pakety, ktoré prechádzajú cez sieť. V tomto projekte sniffer zachytáva
 - UDP pakety
 - TCP pakety 
 
a tlačí informácie o danom pakete na štandartný výstup.

### Príklad spustenia
 ```sh
 $ make
 $ ./ipk-sniffer -i eth0 -p 23 -u -n 3
 ```

### Zoznam odovzdaných súborov
 - ipk-sniffer.c
 - Makefile

### Implementácia extra vlastností
 - argument --help vypíše nápovedu k spusteniu a použitiu programu