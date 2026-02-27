ft alloc *.malloc *.free$ *.calloc *.kalloc *.realloc
ft crypto *.encrypt *.decrypt *.aes *.AES *.blowfish *._des *._rc2 *.serpent *._cbc
ft dylib *.dlopen *.dlsym *.dlclose *.mmap *.LoadLibrary *.GetProcAddress
ft env *.getenv *.putenv *.unsetenv *.setenv *.GetEnvironmentVariable *.SetEnvironmentVariable *.ExpandEnvironmentStrings
ft fs *.open$ *.close *.read$ *.write *.CloseHandle *.FindFirstFileW *._wfopen *._wstat *.ftruncate *.lseek *._chsize *.GetFullPathName *.realpath *.RemoveDirectory *.DeleteFile *.CreateFile *.WriteFile *.UnmapViewOfFile *.CreateFileMapping *.MapViewOfFile *.readlink *.chmod *.fchmod *.chown *.stat *.fstat *.lstat *.fstatat *.lstat64 *.stat64 *.chflags *.fchflags *.lchflags
ft network *.socket *.connect *.bind$ *.listen *.accept *.sendto *.recvfrom *.gethostbyname *.htons *.ntohs
ft process *.getpid *.getppid *.kill *.exit *.abort *.assert *.gethostid *.sethostid *.sysctl
ft stdout ^printf *.puts *.write
ft string *.strcat *.strcpy *.strncpy *.strlen *.strtok *.strstr *.strlcpy *.asprintf *.sprintf *.snprintf
ft tags.py import os from sys import argv for fname in argv[1:]: with open(fname) as f: text = ' '.join(f.read().splitlines()) print('ft %s %s' % (os.path.basename(fname), text))
ft threads *.pthread_create *.pthread_mutex_init *.pthread_cond_init *.CreateThread *.TerminateThread *.WaitForSingleObject *.GetCurrentThreadId
ft time *.settimeofday *.gettimeofday *.time *.adjtime *.ctime *.timed *.date$ *.sleep *.Sleep *.usleep *.clock_nanosleep *.localtime *.asctime *.difftime *.gmtime *.mktime *.timelocal *.timegm *.tzfile *.tzset
