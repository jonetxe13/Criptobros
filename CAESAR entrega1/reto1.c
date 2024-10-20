#include <stdio.h>
#include <string.h>

void print_string (unsigned char a[], int len);


int main() {
 	unsigned char cipher[1000]="tfewzuvekzrczkp zj ivjvimzex rlkyfizqvu ivjkiztkzfej fe zewfidrkzfe rttvjj reu uzjtcfjliv, zetcluzex dvrej wfi gifkvtkzex gvijferc gizmrtp reu gifgizvkrip zewfidrkzfe.zekvxizkp zj xlriuzex rxrzejk zdgifgvi zewfidrkzfe dfuzwztrkzfe fi uvjkiltkzfe, reu zetcluvj vejlizex zewfidrkzfe efe-ivgluzrkzfe reu rlkyvekztzkp.rmrzcrszczkp zj vejlizex kzdvcp reu ivczrscv rttvjj kf reu ljv fw zewfidrkzfe.";
 	int len=strlen(cipher);
	print_string(cipher,len);

	//Rellenar el c�digo aqu�

   	return 0;
}

void print_string (unsigned char a[], int len)
{	
	unsigned char descrifrado[1000];
	for (int i=1; i<26; i++)
	{
		for (int j=0; j<len; j++)
		{
			if((a[j]>='a' && a[j]<='z') ) {
       				if((a[j]+i)>'z'){
					descrifrado[j] = (a[j]+i)-26;
				}
				else{
					descrifrado[j] = (a[j]+i);
				}
			}
			else{ //si es un caracter especial lo imprime
				descrifrado[j] = a[j];
			}
		}
		descrifrado[len] = '\0'; // Asegurarse de que la cadena esté terminada

		char *word = "and";
		char *existe = strstr((char *)descrifrado, word);
		if (existe != NULL) {
		    printf("Palabra 'and' encontrada en: %s\n", descrifrado);
		}
		memset(descrifrado, 0, 1000);
	}
}
