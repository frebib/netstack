## Error Handling
- Error constants should always be returned negative (-ECONNREFUSED) 
- Functions that can return error values should return `int` type
- Zero return values (== 0) indicate success
- Positive return values (>= 0) indicate success (e.g. amount of bytes sent)
