# Reporte: Propuesta de Alteración del Algoritmo SHA-3 Keccak

**Seguridad de Sistemas Informáticos - CC411A**

Escuela de Ciencias de la Computación

_Mg. Manuel Alejandro Quispe Torres_

Universidad Nacional de Ingeniería

**Leonardo Alexander Chacón Roque - 20221002K**

6 de junio del 2026

---

## 1. Objetivo

Modificación experimental del algoritmo criptográfico SHA-3 basado en Keccak-f1600, alterando dinámicamente el orden y comportamiento de sus cinco transformaciones principales mediante una variable denominada `intentos_fallidos`.


## 2. Descripción de la Alteración en SHA-3

El algoritmo Keccak-f1600 utiliza una matriz de estado interna de 5×5 palabras de 64 bits y ejecuta exactamente 24 rondas criptográficas. Esto corresponde a la función `keccak_f1600(state)` del código base, donde el estado se inicializa como `[[0] * 5 for _ in range(5)]` y el bucle recorre `range(24)`.

Cada ronda aplica secuencialmente cinco transformaciones matemáticas:

$$\theta \rightarrow \rho \rightarrow \pi \rightarrow \chi \rightarrow \iota$$

<img width="720" height="585" alt="image" src="https://github.com/user-attachments/assets/8a2e20a5-0f47-4dae-941c-3c10ae1a694a" />

En `keccak_f1600` los pasos $\rho$ y $\pi$ aparecen combinados en un único bucle. Para poder reordenarlos, en la variante se separan en las funciones independientes `theta`, `rho`, `pi`, `chi` e `iota` en el segundo bloque de `implementacion.ipynb`.

<img width="629" height="242" alt="image" src="https://github.com/user-attachments/assets/b394be49-8d73-49e4-a5de-99e04648b4d5" />

### 2.1. Variable dinámica `intentos_fallidos`

Introduce una variable global `intentos_fallidos`, inicializada en `0` y actualizada por la función `registrar_intento_fallido()`. Esta variable controla las cuatro alteraciones siguientes.

<img width="442" height="107" alt="image" src="https://github.com/user-attachments/assets/eafee842-038f-4c36-b922-b61c66e8001a" />

### 2.2. Nuevo orden de transformaciones

El orden clásico se reemplaza parcialmente, cuando `intentos_fallidos >= 3`, por:

$$\theta \rightarrow \rho \rightarrow \chi \rightarrow \pi \rightarrow \sigma \rightarrow \iota$$

<img width="504" height="135" alt="image" src="https://github.com/user-attachments/assets/cd9563b1-d373-4b83-9c7d-ec6c5e9aa36d" />

donde `sigma` es una nueva transformación experimental. Esta bifurcación de orden está implementada en `keccak_f1600_variante(state)`: si `intentos_fallidos < 3` se usa el orden original y, en caso contrario, el orden experimental.

<img width="404" height="122" alt="image" src="https://github.com/user-attachments/assets/169b248c-d612-4f96-a9b4-72c0dac7c318" />

### 2.3. La nueva transformación `sigma`

Corresponde a la función `sigma(state, intentos_fallidos)` que recorre la matriz de estado aplicando un XOR dependiente del contexto y la posición, seguido de una pequeña rotación de bits:

$$\text{state}[x][y] = \text{state}[x][y] \oplus (\text{intentos\\_fallidos} \ll (x+y))$$

Esto dificultaría toda posibilidad de ataques básicos que necesitan del determinismo del algoritmo sin importar el número de intentos fallidos.

<img width="582" height="191" alt="image" src="https://github.com/user-attachments/assets/27d3fb3f-b456-43e1-979e-50e692e20b72" />

### 2.4. Rondas dinámicas

El número de rondas deja de ser constante y pasa a depender del contexto, dentro de `keccak_f1600_variante`:

$$\text{rondas} = \min(24,\ 8 + \text{intentos\\_fallidos})$$

<img width="616" height="71" alt="image" src="https://github.com/user-attachments/assets/709d3025-df72-4f2c-8acd-771a92c7172b" />

En el bloque de demostración (segundo bloque) se simulan 5 intentos fallidos, por lo que el valor efectivo es:

$$\text{rondas} = \min(24,\ 8 + 5) = 13$$

<img width="523" height="72" alt="image" src="https://github.com/user-attachments/assets/32029077-9b2e-47ff-8484-e8aaeaa7cdb7" />

<img width="608" height="393" alt="image" src="https://github.com/user-attachments/assets/3523631c-e953-4f9f-a7f6-9816bcac10bf" />

### 2.5. Constante de ronda dinámica en `iota`

La constante de ronda usada en `iota` se modifica mediante XOR con la misma variable dinámica. Esto está implementado en la función `iota(state, round_idx, intentos_fallidos)` como `RC_modificada = RC[round_idx] ^ intentos_fallidos`:

$$\text{RC}' = \text{RC}[i] \oplus \text{intentos\\_fallidos}$$

<img width="540" height="122" alt="image" src="https://github.com/user-attachments/assets/026a8b9f-74cf-4c22-8c7f-5659c0eddb8c" />

### 2.6. No conmutatividad

Esta propiedad se demuestra experimentalmente mediante el pequeño script de prueba contenido en el segundo bloque de `implementacion.ipynb`: se toma una misma entrada `mensaje = b"password123"` y se comparan el hash del algoritmo original `sha3_256_fips` frente al de la variante propuesta `sha3_256_variante`. Al ejecutarlo, ambos hashes resultan distintos, lo que constituye el contraejemplo práctico de no conmutatividad.

<img width="522" height="226" alt="image" src="https://github.com/user-attachments/assets/cfa7112b-bb42-4a89-b134-61454092293b" />

## 3. Resultados

Al aumentar `intentos_fallidos` el número de rondas crece de 8 a 24 y los pasos se reordenan agregando el paso adicional `sigma`. En consecuencia, el costo computacional aumenta de forma con el número de fallos. Esto se verifica en el primer párrafo de la ejecuci{on del segundo bloque de `implementacion.ipynb`.

<img width="383" height="37" alt="image" src="https://github.com/user-attachments/assets/3fd3e358-724b-4c92-adb7-05166e0a291a" />

Asimismo, debido a la naturaleza no conmutativa de las funciones internas, una modificación en la composición genera un hash final distinto, tal como confirma la comparación del segundo bloque de `implementacion.ipynb`.

<img width="589" height="50" alt="image" src="https://github.com/user-attachments/assets/f981e564-1485-4aff-a28d-ead624730770" />

## 4. Conclusión

La propuesta en `implementacion.ipynb` transforma la permutación estática `keccak_f1600` en una variante dependiente del contexto, `keccak_f1600_variante`, controlada por `intentos_fallidos`. Las cinco alteraciones (rondas dinámicas, reordenamiento, nuevo paso `sigma`, `iota` dinámica y la prueba de no conmutatividad) son pequeñas y están comentadas.
