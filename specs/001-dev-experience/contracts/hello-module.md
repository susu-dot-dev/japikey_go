# Hello Module Interface Contract

## Package: hello

### Function: GetMessage()

**Signature**: `func GetMessage() string`

**Purpose**: Returns a simple "Hello, World!" string to demonstrate basic module functionality.

**Input**: None

**Output**: 
- Type: string
- Value: "Hello, World!"

**Error Handling**: This function does not return errors as it performs a simple operation.

**Usage Example**:
```go
result := hello.GetMessage()
// result == "Hello, World!"
```

## Package: hello (Alternative function)

### Function: GetMessageWithContext(ctx context.Context)

**Signature**: `func GetMessageWithContext(ctx context.Context) (string, error)`

**Purpose**: Returns a simple "Hello, World!" string with context support for more complex operations in the future.

**Input**: 
- ctx: context.Context for cancellation and timeouts

**Output**: 
- string: "Hello, World!"
- error: nil in normal operation

**Error Handling**: Returns context cancellation errors if the context is cancelled.

**Usage Example**:
```go
ctx := context.Background()
result, err := hello.GetMessageWithContext(ctx)
if err != nil {
    // handle error
}
// result == "Hello, World!"
```