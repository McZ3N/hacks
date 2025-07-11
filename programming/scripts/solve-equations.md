---
description: Solve a system of three unknowns, given four equations with sympy
---

# Solve equations

```python
from Crypto.Util.number import long_to_bytes
import sympy

# Values
v1 = 4196604293528562019178729176959696479940189487937638820300425092623669070870963842968690664766177268414970591786532318240478088400508536
v2 = 11553755018372917030893247277947844502733193007054515695939193023629350385471097895533448484666684220755712537476486600303519342608532236
v3 = 14943875659428467087081841480998474044007665197104764079769879270204055794811591927815227928936527971132575961879124968229204795457570030
v4 = 6336816260107995932250378492551290960420748628

# Create variables
x, y, z = sympy.symbols('x y z')

# Equations
equations = [
    x**3 + z**2 + y - v1,
    y**3 + x**2 + z - v2,
    z**3 + y**2 + x - v3,
    x + y + z - v4
]

# Solve the equations
solutions = sympy.solve(equations, (x, y, z))

# Convert from long to bytes
for sol in solutions:
    try:
        cnd1, cnd2, cnd3 = map(int, sol)
        flag_parts = [long_to_bytes(cnd1), long_to_bytes(cnd2), long_to_bytes(cnd3)]
        flag = b''.join(flag_parts)
        print(f"Flag: {flag.decode()}")
    except:
        continue
```
