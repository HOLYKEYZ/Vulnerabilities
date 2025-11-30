// vulnerabilities.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 1. Buffer Overflow
void bufferOverflow() {
    char buf[10];
    gets(buf); // Dangerous: no bounds checking
    printf("You entered: %s\n", buf);
}

// 2. Format String Vulnerability
void formatString() {
    char input[100];
    scanf("%s", input);
    printf(input); // Dangerous: user-controlled format string
}

// 3. Command Injection
void commandInjection() {
    char cmd[100];
    printf("Enter command: ");
    scanf("%s", cmd);
    char fullCmd[150];
    sprintf(fullCmd, "ls %s", cmd); // No sanitization
    system(fullCmd);
}

// 4. Integer Overflow
void integerOverflow() {
    unsigned int a = 4000000000;
    unsigned int b = 4000000000;
    unsigned int c = a + b; // Overflow
    printf("Sum: %u\n", c);
}

// 5. Use After Free
void useAfterFree() {
    char *data = malloc(20);
    strcpy(data, "Hello");
    free(data);
    printf("%s\n", data); // Use after free
}

// 6. Double Free
void doubleFree() {
    char *ptr = malloc(10);
    free(ptr);
    free(ptr); // Double free
}

// 7. Memory Leak
void memoryLeak() {
    char *leak = malloc(100);
    strcpy(leak, "Leaking memory"); // Never freed
}

// 8. Null Pointer Dereference
void nullPointer() {
    char *ptr = NULL;
    printf("%c\n", *ptr); // Crash
}

// 9. Insecure Temporary File
void insecureTempFile() {
    char *tmp = tmpnam(NULL);
    FILE *f = fopen(tmp, "w+"); // Race condition
    fprintf(f, "temp data\n");
    fclose(f);
}

// 10. Stack Overflow (Recursion)
void stackOverflow() {
    stackOverflow(); // Infinite recursion
}

// 11. Race Condition (Simulated)
void raceCondition() {
    FILE *f = fopen("shared.txt", "w");
    sleep(1); // Simulate delay
    fprintf(f, "Race condition!\n");
    fclose(f);
}

// 12. Hardcoded Credentials
void hardcodedSecrets() {
    char *user = "admin";
    char *pass = "password123"; // Hardcoded
    printf("Logging in as %s\n", user);
}

// 13. Unchecked Return Values
void uncheckedReturn() {
    FILE *f = fopen("file.txt", "r");
    char buf[50];
    fread(buf, 1, 100, f); // No check on return value
    fclose(f);
}

// 14. Off-by-One Error
void offByOne() {
    char arr[10];
    for (int i = 0; i <= 10; i++) {
        arr[i] = 'A'; // Writes one byte too far
    }
}

// 15. Insecure Randomness
void insecureRandom() {
    int token = rand(); // Predictable
    printf("Token: %d\n", token);
}

// 16. Path Traversal (Simulated)
void pathTraversal() {
    char filename[100];
    scanf("%s", filename);
    FILE *f = fopen(filename, "r"); // No validation
    if (f) {
        char buf[100];
        fread(buf, 1, 100, f);
        fclose(f);
    }
}

// 17. Deprecated Functions
void deprecatedFunctions() {
    char input[100];
    gets(input); // Deprecated and unsafe
    printf("Input: %s\n", input);
}

// 18. Environment Variable Injection
void envInjection() {
    char *cmd = getenv("MALICIOUS_CMD");
    if (cmd) {
        system(cmd); // Dangerous
    }
}

// 19. Type Confusion (Simulated)
void typeConfusion() {
    void *ptr = malloc(sizeof(int));
    *(double *)ptr = 3.14; // Wrong type cast
    free(ptr);
}

// 20. Uninitialized Memory Use
void uninitializedMemory() {
    char buf[50];
    printf("Data: %s\n", buf); // May contain garbage
}

int main() {
    // Call any function here to test
    bufferOverflow();
    formatString();
    commandInjection();
    integerOverflow();
    useAfterFree();
    doubleFree();
    memoryLeak();
    nullPointer();
    insecureTempFile();
    // stackOverflow(); // Uncomment with caution
    raceCondition();
    hardcodedSecrets();
    uncheckedReturn();
    offByOne();
    insecureRandom();
    pathTraversal();
    deprecatedFunctions();
    envInjection();
    typeConfusion();
    uninitializedMemory();

    return 0;
}