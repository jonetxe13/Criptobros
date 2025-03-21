#!/bin/bash

gcc test.c $1.c -o test -O2 -march=native -lm

# Archivos temporales para almacenar los resultados
enc_file="results_enc.txt"
dec_file="results_dec.txt"
archivo=$1

# Limpiar archivos temporales
> $enc_file
> $dec_file
> resultados_$archivo.txt

mensaje="YourmessagehereYourmessagehere"
for k in {1..8}; do
 echo "Key size: $(($k*32)) bytes">> resultados_$archivo.txt
for i in {1..500}; do
    if [ $i -gt 50 ]; then
        output=$(./test $k)
        enc=$(echo "$output" | grep "Encryption time" | awk '{print $4}')  # Extraer el tiempo de cifrado
        dec=$(echo "$output" | grep "Decryption time" | awk '{print $4}')  # Extraer el tiempo de descifrado
        
        # Guardar resultados en archivos temporales
        echo "$enc" >> $enc_file
        echo "$dec" >> $dec_file
    fi
done

# Calcular la media de los resultados de cifrado (encryption)
total_enc=$(awk '{s+=$1} END {print s}' $enc_file)
count_enc=$(wc -l < $enc_file)
media_enc=$(awk "BEGIN {print $total_enc/$count_enc}")

# Calcular la media de los resultados de descifrado (decryption)
total_dec=$(awk '{s+=$1} END {print s}' $dec_file)
count_dec=$(wc -l < $dec_file)
media_dec=$(awk "BEGIN {print $total_dec/$count_dec}")

# Calcular la desviación típica para cifrado
stdev_enc=$(awk -v mean=$media_enc '{sum+=($1-mean)^2} END {print sqrt(sum/NR)}' $enc_file)

# Calcular la desviación típica para descifrado
stdev_dec=$(awk -v mean=$media_dec '{sum+=($1-mean)^2} END {print sqrt(sum/NR)}' $dec_file)

# Mostrar las medias y desviaciones típicas
echo "La media de los resultados de cifrado es: $media_enc us" >> resultados_$archivo.txt
echo "La desviación típica de los resultados de cifrado es: $stdev_enc us" >> resultados_$archivo.txt
echo "La media de los resultados de descifrado es: $media_dec us" >> resultados_$archivo.txt
echo "La desviación típica de los resultados de descifrado es: $stdev_dec us" >> resultados_$archivo.txt
echo "">> resultados_$archivo.txt

done
cat resultados_$archivo.txt
