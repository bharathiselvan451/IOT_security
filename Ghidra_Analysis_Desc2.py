VULNERABLE_FUNCTIONS = {
    'popen': "* Shares similar risks to system, enabling arbitrary command execution. *",
    'strcpy': "* May cause arbitrary memory overwrite or buffer overflow *",
    'strncpy': "* Potential for arbitrary memory overwrite or buffer overflow *",
    'scanf': "* Prone to format string vulnerabilities and buffer overflow risks. *",
    'realpath': "* Can cause a buffer overflow if the resolved path exceeds the buffer size. *",
    'calloc': "* Similar to malloc, it poses risks of memory corruption. *",
    'fread': "* May cause data leakage or unwanted memory access *",
    'fwrite': "* Risk of buffer overflow *",
    'chdir': "* Can be exploited to alter the working directory, impacting program behavior. *",
    'execve': "* May facilitate the execution of arbitrary binaries, potentially resulting in privilege escalation. *",
    'chown': "* Can be exploited to alter file ownership incorrectly, potentially resulting in privilege escalation. *",
    'close': "* Improper management can cause resource leaks or denial-of-service. *",
    'gets': "* Extremely dangerous, always leads to buffer overflow *",
    'unlink': "* Can result in race conditions or privilege escalation. *",
    'memset': "* Could lead to arbitrary memory overwrite or buffer overflow *",
    'chdir': "* Can be exploited to alter the working directory, impacting program behavior. *",
    'read': "* Risk of file descriptor hijacking or denial-of-service *",
    'abort': "* May cause program termination in an unsafe state, resulting in a denial-of-service. *",
    'fgets': "* If improperly constrained, susceptible to buffer overflows *",
    'realloc': "* May cause arbitrary memory overwrite or buffer overflow *",
    'memcpy': "* Possible memory overwrite or buffer overflow risk *",
    'chmod': "* Can be exploited to incorrectly change file ownership, potentially leading to privilege escalation. *",
    'system': "* Enables the execution of arbitrary commands. *",
    'free': "* May lead to double free or use-after-free vulnerabilities. *",
    'assert': "* If disabled in production, it may conceal important checks, potentially exposing vulnerabilities. *",
    'strcat': "* Risk of buffer overflow from unmanaged string concatenation. *",
    'open': "* Susceptible to TOCTOU (Time-of-Check to Time-of-Use) exploitation. *",
    'sprintf': "* Vulnerable to format string attacks *",
    'printf': "* May cause format string attacks *"
}

