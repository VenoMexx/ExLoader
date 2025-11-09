# Math Hooks

Monitor mathematical function calls.

## Module: `mathmon`

### Hooked APIs

**Exponential/Power:**
- `pow`, `powf` - x^y
- `exp`, `expf` - e^x
- `sqrt`, `sqrtf` - Square root

**Trigonometric:**
- `sin`, `sinf`, `cos`, `cosf`
- `tan`, `tanf`
- `asin`, `acos`, `atan`, `atan2`

**Logarithmic:**
- `log`, `logf` - Natural log
- `log10`, `log10f` - Base-10 log

**Rounding:**
- `ceil`, `ceilf`, `floor`, `floorf`
- `round`, `roundf`

**Other:**
- `fabs`, `fabsf` - Absolute value
- `fmod`, `fmodf` - Modulo

## Event Type: `math.call`

**Sample Event:**
```json
{
  "ts": "2025-11-09T18:40:15.123Z",
  "type": "math.call",
  "api": "pow",
  "a": 2.0,
  "b": 10.0,
  "result": 1024.0,
  "caller": {
    "module": "game.exe",
    "offset": 123456
  }
}
```

**Trigonometry:**
```json
{
  "type": "math.call",
  "api": "sin",
  "a": 1.5707963267948966,
  "result": 1.0
}
```

**Square Root:**
```json
{
  "type": "math.call",
  "api": "sqrt",
  "a": 144.0,
  "result": 12.0
}
```

## Configuration

```json
{
  "modules": ["mathmon"]
}
```

## Use Cases

### Game Engines

Physics calculations, trajectories:
```bash
# Find pow() calls for damage calculations
jq 'select(.api=="pow")' logs/output.jsonl
```

### Scientific Applications

Complex mathematical operations:
```bash
# Track logarithmic operations
jq 'select(.api | startswith("log"))' logs/output.jsonl
```

### Crypto Implementations

Custom algorithms may use math functions:
```bash
# Find modulo operations
jq 'select(.api=="fmod")' logs/output.jsonl
```

## Analysis Patterns

### Find Computation Hotspots

```bash
# Count most-used math functions
jq -r '.api' logs/output.jsonl | sort | uniq -c | sort -rn
```

### Track Specific Calculations

```bash
# Find square root operations
jq 'select(.api=="sqrt") | {input: .a, output: .result}' logs/output.jsonl
```

### Reverse Engineering Formulas

```bash
# Collect pow() calls to deduce algorithm
jq 'select(.api=="pow") | "\(.a)^\(.b) = \(.result)"' logs/output.jsonl
```

## Common Patterns

### 3D Graphics

Frequent `sin`, `cos`, `sqrt` for transformations.

### Physics Simulations

`pow`, `sqrt` for distance/force calculations.

### Audio Processing

`sin`, `cos` for wave generation.

## Limitations

- **Float variants optional**: `powf`, `sinf` may not be hooked on all systems
- **Inline optimizations**: Compiler-inlined math may not be captured
- **SIMD**: Vectorized math (SSE/AVX) not hooked

## Troubleshooting

**"Plugin failed to initialize: mathmon"**

This occurs if `msvcrt.dll` functions can't be hooked:
- Ensure MinGW runtime is present
- Some float variants are optional
- Check logs for specific function failures

---

**Back to:** [Documentation Index](../index.md)
