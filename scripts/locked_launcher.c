/* Static x86_64 Linux RSA trust-boundary launcher: no libc, loader, or shell. */

#if !defined(__x86_64__)
#error "locked launcher supports only x86_64 Linux"
#endif
#if LAUNCH_KIND < 1 || LAUNCH_KIND > 5
#error "LAUNCH_KIND must be between 1 and 5"
#endif
#if !defined(EGSI_RSA_MODULUS_WORDS) || !defined(EGSI_RSA_RR_WORDS) || \
    !defined(EGSI_RSA_N0_INV) || !defined(EGSI_NATIVE_KEY_ID_BYTES) || \
    !defined(EGSI_NATIVE_BUILD_ID_BYTES) || !defined(EGSI_NATIVE_CONTRACT_BYTES) || \
    !defined(EGSI_BOOTSTRAP_SHA256_BYTES) || !defined(EGSI_BOOTSTRAP_SIZE) || \
    !defined(EGSI_BOOTSTRAP_MODE) || \
    !defined(EGSI_PYTHON_SHA256_BYTES) || !defined(EGSI_PYTHON_SIZE) || \
    !defined(EGSI_PYTHON_MODE) || !defined(EGSI_PYTHON_DEVICE) || \
    !defined(EGSI_PYTHON_INODE) || !defined(EGSI_PYTHON_RUNTIME_CLOSURE_BYTES) || \
    !defined(EGSI_PYTHON_RUNTIME_FILE_COUNT) || !defined(EGSI_PYTHON_RUNTIME_ENTRY_COUNT) || \
    !defined(EGSI_PYTHON_RUNTIME_PRELOAD_COUNT) || \
    !defined(EGSI_PYTHON_RUNTIME_ENTRIES) || \
    !defined(EGSI_PYTHON_RUNTIME_PRELOAD_INDICES) || \
    !defined(EGSI_IMPORT_ROOT_COUNT) || !defined(EGSI_IMPORT_ROOTS) || \
    !defined(EGSI_STARTUP_CODE_CLOSURE_BYTES) || \
    !defined(EGSI_STARTUP_CODE_FILE_COUNT) || \
    !defined(EGSI_STARTUP_CODE_DIRECTORY_COUNT) || \
    !defined(EGSI_STARTUP_CODE_ABSENT_COUNT) || \
    !defined(EGSI_STARTUP_CODE_TOTAL_BYTES) || \
    !defined(EGSI_STARTUP_CODE_PYCACHE_PREFIX) || \
    !defined(EGSI_STARTUP_CODE_FILES) || \
    !defined(EGSI_STARTUP_CODE_DIRECTORIES) || \
    !defined(EGSI_STARTUP_CODE_ABSENT_PATHS) || \
    !defined(EGSI_SOURCE_ROOT) || !defined(EGSI_PYTHON_PATH) || \
    !defined(EGSI_BOOTSTRAP_PATH) || !defined(EGSI_RECEIPT_SELF) || \
    !defined(EGSI_RERUN_SELF) || !defined(EGSI_VERIFIER_SELF) || \
    !defined(EGSI_LIVE_RUN_SELF) || !defined(EGSI_LIVE_VERIFY_SELF)
#error "generated native RSA build header is required"
#endif
#if (LAUNCH_KIND == 1 || LAUNCH_KIND == 2 || LAUNCH_KIND == 4) && !defined(EGSI_HAS_RSA_SIGNING_EXPONENT)
#error "native signer requires an RSA signing exponent"
#endif
#if (LAUNCH_KIND == 3 || LAUNCH_KIND == 5) && defined(EGSI_HAS_RSA_SIGNING_EXPONENT)
#error "public verifier must not receive an RSA signing exponent"
#endif

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned long usize;

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_fstat 5
#define SYS_pread64 17
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_fsync 74
#define SYS_unlink 87
#define SYS_readlink 89
#define SYS_fcntl 72
#define SYS_getrlimit 97
#define SYS_setrlimit 160
#define SYS_prctl 157
#define SYS_openat 257
#define SYS_newfstatat 262
#define SYS_mkdirat 258
#define SYS_unlinkat 263
#define SYS_renameat2 316
#define SYS_clock_gettime 228
#define SYS_getrandom 318

#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define O_EXCL 0200
#define O_NONBLOCK 04000
#define O_DIRECTORY 0200000
#define O_NOFOLLOW 0400000
#define O_CLOEXEC 02000000
#define RENAME_NOREPLACE 1
#define S_IFMT 0170000
#define S_IFREG 0100000
#define S_IFDIR 0040000
#define PR_SET_DUMPABLE 4
#define PR_GET_DUMPABLE 3
#define RLIMIT_CORE 4
#define F_SETFD 2
#define AT_FDCWD -100
#define AT_SYMLINK_NOFOLLOW 0x100

#define RSA_WORDS 64
#define RSA_BYTES 256
#define MAX_USER_ARGS 48
#define MAX_PATH 1024
#define MAX_CAPTURE 4096
#define MAX_DIRECTORY_CHAIN 32
#define MAX_PYTHON_RUNTIME_ENTRIES 257
#define MAX_PYTHON_PRELOAD 16384
#define MAX_PYTHON_RUNTIME_FILE_BYTES (64UL * 1024UL * 1024UL)
#define MAX_IMPORT_ROOTS 8
#define MAX_STARTUP_CODE_FILES 4096
#define MAX_STARTUP_CODE_DIRECTORIES 1024
#define MAX_STARTUP_CODE_ABSENT_PATHS 16
#define MAX_STARTUP_CODE_FILE_BYTES (4UL * 1024UL * 1024UL)
#define MAX_ARTIFACT_BYTES (16UL * 1024UL * 1024UL)
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1

struct kernel_timespec { long seconds; long nanoseconds; };
struct kernel_stat {
    u64 device, inode, links;
    u32 mode, uid, gid, padding;
    u64 rdevice;
    long size, block_size, blocks;
    struct kernel_timespec access_time, modification_time, change_time;
    long reserved[3];
};
struct kernel_rlimit { u64 current, maximum; };
struct file_anchor { struct kernel_stat identity; u8 digest[32]; };
struct python_runtime_contract_entry { const char *path; struct kernel_stat identity; u8 digest[32]; };
struct python_import_root_entry { const char *path; usize count; struct kernel_stat identities[MAX_DIRECTORY_CHAIN]; };
struct python_startup_file_entry { const char *path; struct kernel_stat identity; u8 digest[32]; };
struct python_startup_directory_entry { const char *path; struct kernel_stat identity; };
struct directory_chain {
    char path[MAX_PATH];
    struct kernel_stat identities[MAX_DIRECTORY_CHAIN];
    int fds[MAX_DIRECTORY_CHAIN];
    usize count,metadata_from;
};
struct python_runtime_anchor {
    int fds[MAX_PYTHON_RUNTIME_ENTRIES];
    struct directory_chain parents[MAX_PYTHON_RUNTIME_ENTRIES];
    usize parent_count;
};
struct python_startup_anchor {
    int file_fds[MAX_STARTUP_CODE_FILES];
    int directory_fds[MAX_STARTUP_CODE_DIRECTORIES];
};

static const u32 rsa_modulus[RSA_WORDS] = EGSI_RSA_MODULUS_WORDS;
static const u32 rsa_rr[RSA_WORDS] = EGSI_RSA_RR_WORDS;
#if LAUNCH_KIND == 1 || LAUNCH_KIND == 2 || LAUNCH_KIND == 4
static const u32 rsa_signing_exponent[RSA_WORDS] = EGSI_RSA_SIGNING_EXPONENT_WORDS;
#endif
static const u8 native_key_id[32] = EGSI_NATIVE_KEY_ID_BYTES;
static const u8 native_build_id[32] = EGSI_NATIVE_BUILD_ID_BYTES;
static const u8 native_contract_value[32] = EGSI_NATIVE_CONTRACT_BYTES;
static const u8 bootstrap_sha256[32] = EGSI_BOOTSTRAP_SHA256_BYTES;
static const u8 python_sha256[32] = EGSI_PYTHON_SHA256_BYTES;
static const u8 python_runtime_closure[32] = EGSI_PYTHON_RUNTIME_CLOSURE_BYTES;
static const u8 startup_code_closure[32] = EGSI_STARTUP_CODE_CLOSURE_BYTES;
static const struct python_runtime_contract_entry python_runtime_entries[EGSI_PYTHON_RUNTIME_ENTRY_COUNT] = EGSI_PYTHON_RUNTIME_ENTRIES;
static const u32 python_runtime_preload_indices[EGSI_PYTHON_RUNTIME_PRELOAD_COUNT] = EGSI_PYTHON_RUNTIME_PRELOAD_INDICES;
static const struct python_import_root_entry python_import_roots[EGSI_IMPORT_ROOT_COUNT] = EGSI_IMPORT_ROOTS;
static const struct python_startup_file_entry startup_code_files[EGSI_STARTUP_CODE_FILE_COUNT] = EGSI_STARTUP_CODE_FILES;
static const struct python_startup_directory_entry startup_code_directories[EGSI_STARTUP_CODE_DIRECTORY_COUNT] = EGSI_STARTUP_CODE_DIRECTORIES;
static const char *startup_code_absent_paths[EGSI_STARTUP_CODE_ABSENT_COUNT] = EGSI_STARTUP_CODE_ABSENT_PATHS;
static struct python_runtime_anchor held_python_runtime;
static struct directory_chain held_python_import_roots[MAX_IMPORT_ROOTS];
static struct python_startup_anchor held_python_startup;
static const char python_path[] = EGSI_PYTHON_PATH;
static const char bootstrap_path[] = EGSI_BOOTSTRAP_PATH;
static const char source_root[] = EGSI_SOURCE_ROOT;
static const char receipt_self[] = EGSI_RECEIPT_SELF;
static const char rerun_self[] = EGSI_RERUN_SELF;
static const char verifier_self[] = EGSI_VERIFIER_SELF;
static const char live_run_self[] = EGSI_LIVE_RUN_SELF;
static const char live_verify_self[] = EGSI_LIVE_VERIFY_SELF;
static const char proc_self_exe[] = "/proc/self/exe";
static const char proc_self_status[] = "/proc/self/status";
static const char sidecar_suffix[] = ".native-attestation";
static const char algorithm[] = "rsa-2048-sha256-pkcs1-v1_5";
static const char focused_basename[] = "offline-focused-receipt.json";
static const char full_basename[] = "offline-full-receipt.json";
static const char report_basename[] = "first-case-hard-gate.json";
static const char focused_domain[] = "egsi.test-receipt.focused.v1";
static const char full_domain[] = "egsi.test-receipt.full.v1";
static const char report_domain[] = "egsi.first-case-report.v1";
static const char live_domain[] = "egsi.fail-fast-live.v1";
static const char startup_pycache_option[] = "pycache_prefix=" EGSI_STARTUP_CODE_PYCACHE_PREFIX;

#if LAUNCH_KIND == 1
static const char expected_self[] = EGSI_RECEIPT_SELF;
static const char bootstrap_mode[] = "run-test-receipt";
#elif LAUNCH_KIND == 2
static const char expected_self[] = EGSI_RERUN_SELF;
static const char bootstrap_mode[] = "rerun-first-case";
#elif LAUNCH_KIND == 3
static const char expected_self[] = EGSI_VERIFIER_SELF;
static const char bootstrap_mode[] = "verify-first-case";
#elif LAUNCH_KIND == 4
static const char expected_self[] = EGSI_LIVE_RUN_SELF;
static const char bootstrap_mode[] = "run-fail-fast-enrich";
#else
static const char expected_self[] = EGSI_LIVE_VERIFY_SELF;
static const char bootstrap_mode[] = "verify-fail-fast-enrich";
#endif

static char env_path[] = "PATH=/usr/bin:/bin";
static char env_lang[] = "LANG=C.UTF-8";
static char env_lc_all[] = "LC_ALL=C.UTF-8";
static char env_tz[] = "TZ=UTC";
static char env_home[] = "HOME=/nonexistent";
static char env_tmpdir[] = "TMPDIR=/tmp";
static char env_no_bytecode[] = "PYTHONDONTWRITEBYTECODE=1";
static char env_no_plugins[] = "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1";

static long syscall0(long n) { long r; __asm__ volatile("syscall":"=a"(r):"a"(n):"rcx","r11","memory"); return r; }
static long syscall1(long n,long a) { long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a):"rcx","r11","memory"); return r; }
static long syscall2(long n,long a,long b) { long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b):"rcx","r11","memory"); return r; }
static long syscall3(long n,long a,long b,long c) { long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return r; }
static long syscall4(long n,long a,long b,long c,long d) { long r; register long r10 __asm__("r10")=d; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10):"rcx","r11","memory"); return r; }
static long syscall5(long n,long a,long b,long c,long d,long e) { long r; register long r10 __asm__("r10")=d; register long r8 __asm__("r8")=e; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8):"rcx","r11","memory"); return r; }

static usize string_length(const char *v) { usize n=0; while(v[n]!='\0') ++n; return n; }
static int string_equal(const char *a,const char *b) { usize i=0; while(a[i]&&b[i]) { if(a[i]!=b[i]) return 0; ++i; } return a[i]==b[i]; }
static void copy_bytes(u8 *d,const u8 *s,usize n) { usize i; for(i=0;i<n;++i)d[i]=s[i]; }
static void zero_bytes(u8 *d,usize n) { volatile u8 *p=d; while(n)*p++=0,n--; }
static int constant_equal(const u8 *a,const u8 *b,usize n) { u8 d=0;usize i;for(i=0;i<n;++i)d|=(u8)(a[i]^b[i]);return d==0; }
static void write_text(int fd,const char *s) { usize o=0,n=string_length(s);while(o<n){long w=syscall3(SYS_write,fd,(long)(s+o),(long)(n-o));if(w<=0)return;o+=(usize)w;} }
static void diagnostic(const char *s) { write_text(2,s); }

static int is_value(const char *v) { return v&&v[0]&&!(v[0]=='-'&&v[1]=='-'); }
static int path_is_canonical(const char *v) {
    usize n,start,i;if(!is_value(v)||v[0]!='/')return 0;n=string_length(v);if(n<2||n>=MAX_PATH||v[n-1]=='/')return 0;start=1;
    for(i=1;i<=n;++i){char c=v[i];if(c!='\0'&&(c<33||c>126||c=='='))return 0;if(c=='/'||c=='\0'){usize k=i-start;if(k==0||(k==1&&v[start]=='.')||(k==2&&v[start]=='.'&&v[start+1]=='.'))return 0;start=i+1;}}
    return 1;
}
static int append_string(char *d,usize cap,usize *n,const char *v){usize m=string_length(v),i;if(*n+m>=cap)return 0;for(i=0;i<m;++i)d[*n+i]=v[i];*n+=m;d[*n]='\0';return 1;}
static int append_decimal(char *d,usize cap,usize *n,unsigned long v){char r[32];usize k=0;if(v==0)return append_string(d,cap,n,"0");while(v&&k<sizeof(r)){r[k++]=(char)('0'+v%10);v/=10;}if(*n+k>=cap)return 0;while(k)d[(*n)++]=r[--k];d[*n]='\0';return 1;}
static int append_octal4(char *d,usize cap,usize *n,unsigned long v){char raw[5];int i;if(v>07777UL||*n+4>=cap)return 0;for(i=3;i>=0;--i){raw[i]=(char)('0'+(v&7UL));v>>=3;}raw[4]='\0';return append_string(d,cap,n,raw);}
static const char *path_basename(const char *p){const char *r=p;usize i;for(i=0;p[i];++i)if(p[i]=='/')r=p+i+1;return r;}
static int parent_path(const char *p,char out[MAX_PATH]){usize n=string_length(p),s=n,i;while(s>0&&p[s]!='/')--s;if(s==0||s>=MAX_PATH)return 0;for(i=0;i<s;++i)out[i]=p[i];out[s]='\0';return 1;}
static int concat2(char out[MAX_PATH],const char *a,const char *b){usize n=0;out[0]='\0';return append_string(out,MAX_PATH,&n,a)&&append_string(out,MAX_PATH,&n,b);}

static int self_path_is_exact(void){char p[MAX_PATH];long n=syscall3(SYS_readlink,(long)proc_self_exe,(long)p,sizeof(p)-1);if(n<0||(usize)n!=string_length(expected_self))return 0;p[n]='\0';return string_equal(p,expected_self);}
static int fd_path_is_exact(int fd,const char *expected){char link[64],p[MAX_PATH];usize n=0;long r;link[0]='\0';if(!append_string(link,sizeof(link),&n,"/proc/self/fd/")||!append_decimal(link,sizeof(link),&n,(unsigned long)fd))return 0;r=syscall3(SYS_readlink,(long)link,(long)p,sizeof(p)-1);if(r<0||(usize)r!=string_length(expected))return 0;p[r]='\0';return string_equal(p,expected);}
static int stat_expected(const struct kernel_stat *s,u32 mode,usize limit){return(s->mode&S_IFMT)==S_IFREG&&(s->mode&07777U)==mode&&s->links==1&&s->size>=0&&(usize)s->size<=limit;}
static int directory_stat_expected(const struct kernel_stat *s){return(s->mode&S_IFMT)==S_IFDIR&&s->links>=1;}
static int stat_same(const struct kernel_stat *a,const struct kernel_stat *b){return a->device==b->device&&a->inode==b->inode&&a->links==b->links&&a->mode==b->mode&&a->uid==b->uid&&a->gid==b->gid&&a->size==b->size&&a->modification_time.seconds==b->modification_time.seconds&&a->modification_time.nanoseconds==b->modification_time.nanoseconds&&a->change_time.seconds==b->change_time.seconds&&a->change_time.nanoseconds==b->change_time.nanoseconds;}

static int chain_directory_stat_expected(const struct kernel_stat *s){return(s->mode&S_IFMT)==S_IFDIR&&s->links>=1;}
static int directory_identity_same(const struct kernel_stat *a,const struct kernel_stat *b){return a->device==b->device&&a->inode==b->inode&&a->mode==b->mode&&a->uid==b->uid&&a->gid==b->gid;}
static usize directory_path_index(const char *path){usize i,count=0;for(i=1;path[i];++i)if(path[i]=='/')++count;return count+1;}
static int path_is_at_or_below(const char *path,const char *base){usize i=0;while(base[i]&&path[i]==base[i])++i;return base[i]=='\0'&&(path[i]=='\0'||path[i]=='/');}
static int system_shared_path(const char *path){return path_is_at_or_below(path,"/usr")||path_is_at_or_below(path,"/lib")||path_is_at_or_below(path,"/lib64");}
static int system_directory_stat_expected(const struct kernel_stat *s){return chain_directory_stat_expected(s)&&(s->uid==0U||s->uid==65534U)&&(s->mode&0022U)==0;}
static int directory_chain_anchor_same(const struct directory_chain *chain,usize index,const struct kernel_stat *a,const struct kernel_stat *b){return directory_identity_same(a,b)&&(index<chain->metadata_from||stat_same(a,b))&&(chain->metadata_from!=chain->count||system_directory_stat_expected(a));}
static void initialize_directory_chain(struct directory_chain *chain){usize i;zero_bytes((u8*)chain,sizeof(*chain));for(i=0;i<MAX_DIRECTORY_CHAIN;++i)chain->fds[i]=-1;}
static void close_directory_chain(struct directory_chain *chain){usize i;for(i=0;i<chain->count&&i<MAX_DIRECTORY_CHAIN;++i){if(chain->fds[i]>=0)syscall1(SYS_close,chain->fds[i]);chain->fds[i]=-1;}chain->count=0;chain->metadata_from=0;chain->path[0]='\0';zero_bytes((u8*)chain->identities,sizeof(chain->identities));}
static int capture_directory_component(long fd,const char *path,struct kernel_stat *out){struct kernel_stat before,after;if(fd<0||syscall2(SYS_fstat,fd,(long)&before)<0||!chain_directory_stat_expected(&before)||!fd_path_is_exact((int)fd,path)||syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after)||!fd_path_is_exact((int)fd,path))return 0;copy_bytes((u8*)out,(const u8*)&after,sizeof(after));return 1;}
static int capture_directory_chain(const char *path,struct directory_chain *chain){char name[MAX_PATH],prefix[MAX_PATH],stable_parent[MAX_PATH];usize pos=1,prefix_n=0,path_n=0;long fd=-1;int ok=0;close_directory_chain(chain);initialize_directory_chain(chain);if(!path_is_canonical(path))return 0;fd=syscall3(SYS_open,(long)"/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,0);if(fd<0||!capture_directory_component(fd,"/",&chain->identities[0]))goto done;chain->fds[0]=(int)fd;fd=-1;chain->count=1;prefix[0]='\0';while(path[pos]){usize start=pos,end,n,i;while(path[pos]&&path[pos]!='/')++pos;end=pos;n=end-start;if(n==0||n>=sizeof(name)||chain->count>=MAX_DIRECTORY_CHAIN)goto done;for(i=0;i<n;++i)name[i]=path[start+i];name[n]='\0';if(!append_string(prefix,sizeof(prefix),&prefix_n,"/")||!append_string(prefix,sizeof(prefix),&prefix_n,name))goto done;fd=syscall4(SYS_openat,chain->fds[chain->count-1],(long)name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,0);if(fd<0||!capture_directory_component(fd,prefix,&chain->identities[chain->count]))goto done;chain->fds[chain->count++]=(int)fd;fd=-1;if(path[pos]=='/')++pos;}chain->path[0]='\0';if(!append_string(chain->path,sizeof(chain->path),&path_n,path))goto done;if(system_shared_path(path))chain->metadata_from=chain->count;else if(parent_path(source_root,stable_parent)&&path_is_at_or_below(path,stable_parent))chain->metadata_from=directory_path_index(stable_parent);else chain->metadata_from=chain->count-2;if(chain->metadata_from>chain->count)goto done;ok=1;done:if(fd>=0)syscall1(SYS_close,fd);if(!ok)close_directory_chain(chain);zero_bytes((u8*)name,sizeof(name));zero_bytes((u8*)prefix,sizeof(prefix));zero_bytes((u8*)stable_parent,sizeof(stable_parent));return ok;}
static int directory_chain_matches(const struct directory_chain *chain){char name[MAX_PATH],prefix[MAX_PATH];usize pos=1,prefix_n=0,index=1;long current=-1;struct kernel_stat before,after,observed;int ok=0;if(chain->count<2||chain->count>MAX_DIRECTORY_CHAIN||chain->metadata_from>chain->count||!path_is_canonical(chain->path))return 0;if(syscall2(SYS_fstat,chain->fds[0],(long)&before)<0||!chain_directory_stat_expected(&before)||!directory_chain_anchor_same(chain,0,&before,&chain->identities[0])||!fd_path_is_exact(chain->fds[0],"/"))goto done;current=syscall3(SYS_open,(long)"/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,0);if(current<0||syscall2(SYS_fstat,current,(long)&observed)<0||!directory_chain_anchor_same(chain,0,&observed,&chain->identities[0])||!fd_path_is_exact((int)current,"/"))goto done;syscall1(SYS_close,current);current=-1;prefix[0]='\0';while(chain->path[pos]){usize start=pos,end,n,i;while(chain->path[pos]&&chain->path[pos]!='/')++pos;end=pos;n=end-start;if(n==0||n>=sizeof(name)||index>=chain->count)goto done;for(i=0;i<n;++i)name[i]=chain->path[start+i];name[n]='\0';if(!append_string(prefix,sizeof(prefix),&prefix_n,"/")||!append_string(prefix,sizeof(prefix),&prefix_n,name))goto done;if(syscall2(SYS_fstat,chain->fds[index],(long)&before)<0||!chain_directory_stat_expected(&before)||!directory_chain_anchor_same(chain,index,&before,&chain->identities[index])||!fd_path_is_exact(chain->fds[index],prefix))goto done;current=syscall4(SYS_openat,chain->fds[index-1],(long)name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,0);if(current<0||syscall2(SYS_fstat,current,(long)&observed)<0||!directory_chain_anchor_same(chain,index,&observed,&chain->identities[index])||!fd_path_is_exact((int)current,prefix))goto done;syscall1(SYS_close,current);current=-1;if(syscall2(SYS_fstat,chain->fds[index],(long)&after)<0||!stat_same(&before,&after)||!directory_chain_anchor_same(chain,index,&after,&chain->identities[index]))goto done;++index;if(chain->path[pos]=='/')++pos;}if(index!=chain->count)goto done;ok=1;done:if(current>=0)syscall1(SYS_close,current);zero_bytes((u8*)name,sizeof(name));zero_bytes((u8*)prefix,sizeof(prefix));zero_bytes((u8*)&before,sizeof(before));zero_bytes((u8*)&after,sizeof(after));zero_bytes((u8*)&observed,sizeof(observed));return ok;}
static int refresh_directory_chain_leaf_after_owned_mutation(struct directory_chain *chain){usize index;long observed_fd=-1;struct kernel_stat before,after,observed;int ok=0;if(chain->count<2||chain->count>MAX_DIRECTORY_CHAIN||!path_is_canonical(chain->path))return 0;index=chain->count-1;if(syscall2(SYS_fstat,chain->fds[index],(long)&before)<0||!chain_directory_stat_expected(&before)||!directory_identity_same(&before,&chain->identities[index])||!fd_path_is_exact(chain->fds[index],chain->path))goto done;observed_fd=syscall3(SYS_open,(long)chain->path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,0);if(observed_fd<0||syscall2(SYS_fstat,observed_fd,(long)&observed)<0||!chain_directory_stat_expected(&observed)||!directory_identity_same(&before,&observed)||!stat_same(&before,&observed)||!fd_path_is_exact((int)observed_fd,chain->path))goto done;if(syscall2(SYS_fstat,chain->fds[index],(long)&after)<0||!stat_same(&before,&after)||!fd_path_is_exact(chain->fds[index],chain->path))goto done;copy_bytes((u8*)&chain->identities[index],(const u8*)&after,sizeof(after));ok=directory_chain_matches(chain);done:if(observed_fd>=0)syscall1(SYS_close,observed_fd);zero_bytes((u8*)&before,sizeof(before));zero_bytes((u8*)&after,sizeof(after));zero_bytes((u8*)&observed,sizeof(observed));return ok;}
static int directory_chain_leaf_fd(const struct directory_chain *chain){if(chain->count<2||chain->count>MAX_DIRECTORY_CHAIN)return-1;return chain->fds[chain->count-1];}
static int ensure_directory_exists(const char *path){char parent[MAX_PATH];struct directory_chain chain;long result;int parent_fd,ok=0;initialize_directory_chain(&chain);if(capture_directory_chain(path,&chain)){ok=directory_chain_matches(&chain);goto done;}if(!parent_path(path,parent)||!capture_directory_chain(parent,&chain)||(parent_fd=directory_chain_leaf_fd(&chain))<0||!directory_chain_matches(&chain))goto done;result=syscall3(SYS_mkdirat,parent_fd,(long)path_basename(path),0700);if(result<0&&result!=-17)goto done;close_directory_chain(&chain);initialize_directory_chain(&chain);ok=capture_directory_chain(path,&chain)&&directory_chain_matches(&chain);done:close_directory_chain(&chain);zero_bytes((u8*)parent,sizeof(parent));return ok;}

struct sha256_context{u32 state[8];u64 bits;u8 buffer[64];usize buffered;};
static u32 ror(u32 v,u32 n){return(v>>n)|(v<<(32U-n));}
static u32 be32(const u8 *v){return((u32)v[0]<<24)|((u32)v[1]<<16)|((u32)v[2]<<8)|v[3];}
static void put32(u8 *o,u32 v){o[0]=(u8)(v>>24);o[1]=(u8)(v>>16);o[2]=(u8)(v>>8);o[3]=(u8)v;}
static void sha_transform(struct sha256_context *c,const u8 block[64]){
    static const u32 k[64]={0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
    u32 w[64],a,b,d,e,f,g,h,t1,t2,x;usize i;for(i=0;i<16;++i)w[i]=be32(block+i*4);for(i=16;i<64;++i){u32 s0=ror(w[i-15],7)^ror(w[i-15],18)^(w[i-15]>>3);u32 s1=ror(w[i-2],17)^ror(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}a=c->state[0];b=c->state[1];x=c->state[2];d=c->state[3];e=c->state[4];f=c->state[5];g=c->state[6];h=c->state[7];for(i=0;i<64;++i){u32 s1=ror(e,6)^ror(e,11)^ror(e,25);u32 ch=(e&f)^((~e)&g);u32 s0=ror(a,2)^ror(a,13)^ror(a,22);u32 maj=(a&b)^(a&x)^(b&x);t1=h+s1+ch+k[i]+w[i];t2=s0+maj;h=g;g=f;f=e;e=d+t1;d=x;x=b;b=a;a=t1+t2;}c->state[0]+=a;c->state[1]+=b;c->state[2]+=x;c->state[3]+=d;c->state[4]+=e;c->state[5]+=f;c->state[6]+=g;c->state[7]+=h;
}
static void sha_init(struct sha256_context *c){static const u32 s[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};usize i;for(i=0;i<8;++i)c->state[i]=s[i];c->bits=0;c->buffered=0;}
static void sha_update(struct sha256_context *c,const u8 *v,usize n){usize o=0;c->bits+=(u64)n*8U;while(o<n){usize a=64-c->buffered,t=n-o<a?n-o:a;copy_bytes(c->buffer+c->buffered,v+o,t);c->buffered+=t;o+=t;if(c->buffered==64){sha_transform(c,c->buffer);c->buffered=0;}}}
static void sha_final(struct sha256_context *c,u8 out[32]){u64 bits=c->bits;usize i;c->buffer[c->buffered++]=0x80;if(c->buffered>56){while(c->buffered<64)c->buffer[c->buffered++]=0;sha_transform(c,c->buffer);c->buffered=0;}while(c->buffered<56)c->buffer[c->buffered++]=0;for(i=0;i<8;++i)c->buffer[63-i]=(u8)(bits>>(i*8));sha_transform(c,c->buffer);for(i=0;i<8;++i)put32(out+i*4,c->state[i]);zero_bytes((u8*)c,sizeof(*c));}
static void sha_bytes(const u8 *v,usize n,u8 out[32]){struct sha256_context c;sha_init(&c);sha_update(&c,v,n);sha_final(&c,out);}

static int bn_compare(const u32 *a,const u32 *b){int i;for(i=RSA_WORDS-1;i>=0;--i){if(a[i]>b[i])return 1;if(a[i]<b[i])return-1;}return 0;}
static void bn_sub(u32 *a,const u32 *b){u64 borrow=0;usize i;for(i=0;i<RSA_WORDS;++i){u64 sub=(u64)b[i]+borrow;u32 old=a[i];a[i]=(u32)((u64)old-sub);borrow=((u64)old<sub);}}
static void mont_mul(const u32 *a,const u32 *b,u32 *out){
    u32 t[RSA_WORDS*2+1];usize i,j,k;u64 carry,uv;zero_bytes((u8*)t,sizeof(t));
    for(i=0;i<RSA_WORDS;++i){carry=0;for(j=0;j<RSA_WORDS;++j){uv=(u64)a[i]*(u64)b[j]+(u64)t[i+j]+carry;t[i+j]=(u32)uv;carry=uv>>32;}k=i+RSA_WORDS;while(carry){uv=(u64)t[k]+carry;t[k]=(u32)uv;carry=uv>>32;++k;}}
    for(i=0;i<RSA_WORDS;++i){u32 m=(u32)((u64)t[i]*(u64)EGSI_RSA_N0_INV);carry=0;for(j=0;j<RSA_WORDS;++j){uv=(u64)m*(u64)rsa_modulus[j]+(u64)t[i+j]+carry;t[i+j]=(u32)uv;carry=uv>>32;}k=i+RSA_WORDS;while(carry){uv=(u64)t[k]+carry;t[k]=(u32)uv;carry=uv>>32;++k;}}
    for(i=0;i<RSA_WORDS;++i)out[i]=t[i+RSA_WORDS];if(t[RSA_WORDS*2]||bn_compare(out,rsa_modulus)>=0)bn_sub(out,rsa_modulus);zero_bytes((u8*)t,sizeof(t));
}
static void bn_from_be(const u8 in[RSA_BYTES],u32 out[RSA_WORDS]){usize i;for(i=0;i<RSA_WORDS;++i){usize o=RSA_BYTES-4*(i+1);out[i]=((u32)in[o]<<24)|((u32)in[o+1]<<16)|((u32)in[o+2]<<8)|in[o+3];}}
static void bn_to_be(const u32 in[RSA_WORDS],u8 out[RSA_BYTES]){usize i;for(i=0;i<RSA_WORDS;++i){usize o=RSA_BYTES-4*(i+1);out[o]=(u8)(in[i]>>24);out[o+1]=(u8)(in[i]>>16);out[o+2]=(u8)(in[i]>>8);out[o+3]=(u8)in[i];}}
static void to_mont(const u32 in[RSA_WORDS],u32 out[RSA_WORDS]){mont_mul(in,rsa_rr,out);}
static void from_mont(const u32 in[RSA_WORDS],u32 out[RSA_WORDS]){u32 one[RSA_WORDS];zero_bytes((u8*)one,sizeof(one));one[0]=1;mont_mul(in,one,out);zero_bytes((u8*)one,sizeof(one));}
#if LAUNCH_KIND == 1 || LAUNCH_KIND == 2 || LAUNCH_KIND == 4
static void private_modexp(const u32 base[RSA_WORDS],u32 out[RSA_WORDS]){u32 one[RSA_WORDS],r[RSA_WORDS],x[RSA_WORDS],tmp[RSA_WORDS];int bit;zero_bytes((u8*)one,sizeof(one));one[0]=1;to_mont(one,r);to_mont(base,x);for(bit=2047;bit>=0;--bit){mont_mul(r,r,tmp);copy_bytes((u8*)r,(u8*)tmp,sizeof(r));if((rsa_signing_exponent[(unsigned)bit/32]>>((unsigned)bit%32))&1U){mont_mul(r,x,tmp);copy_bytes((u8*)r,(u8*)tmp,sizeof(r));}}from_mont(r,out);zero_bytes((u8*)one,sizeof(one));zero_bytes((u8*)r,sizeof(r));zero_bytes((u8*)x,sizeof(x));zero_bytes((u8*)tmp,sizeof(tmp));}
#endif
static void public_modexp(const u32 base[RSA_WORDS],u32 out[RSA_WORDS]){u32 one[RSA_WORDS],r[RSA_WORDS],x[RSA_WORDS],tmp[RSA_WORDS];int bit;zero_bytes((u8*)one,sizeof(one));one[0]=1;to_mont(one,r);to_mont(base,x);for(bit=16;bit>=0;--bit){mont_mul(r,r,tmp);copy_bytes((u8*)r,(u8*)tmp,sizeof(r));if(bit==16||bit==0){mont_mul(r,x,tmp);copy_bytes((u8*)r,(u8*)tmp,sizeof(r));}}from_mont(r,out);zero_bytes((u8*)one,sizeof(one));zero_bytes((u8*)r,sizeof(r));zero_bytes((u8*)x,sizeof(x));zero_bytes((u8*)tmp,sizeof(tmp));}
static void encoded_message(const u8 digest[32],u8 em[RSA_BYTES]){static const u8 prefix[19]={0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};usize i;em[0]=0;em[1]=1;for(i=2;i<204;++i)em[i]=0xff;em[204]=0;copy_bytes(em+205,prefix,sizeof(prefix));copy_bytes(em+224,digest,32);}
#if LAUNCH_KIND == 1 || LAUNCH_KIND == 2 || LAUNCH_KIND == 4
static int rsa_sign(const u8 *message,usize n,u8 signature[RSA_BYTES]){u8 digest[32],em[RSA_BYTES];u32 input[RSA_WORDS],output[RSA_WORDS];sha_bytes(message,n,digest);encoded_message(digest,em);bn_from_be(em,input);if(bn_compare(input,rsa_modulus)>=0)return 0;private_modexp(input,output);bn_to_be(output,signature);zero_bytes(digest,sizeof(digest));zero_bytes(em,sizeof(em));zero_bytes((u8*)input,sizeof(input));zero_bytes((u8*)output,sizeof(output));return 1;}
#endif
static int rsa_verify(const u8 *message,usize n,const u8 signature[RSA_BYTES]){u8 digest[32],expected[RSA_BYTES],observed[RSA_BYTES];u32 input[RSA_WORDS],output[RSA_WORDS];int ok=0;bn_from_be(signature,input);if(bn_compare(input,rsa_modulus)>=0)goto done;public_modexp(input,output);bn_to_be(output,observed);sha_bytes(message,n,digest);encoded_message(digest,expected);ok=constant_equal(expected,observed,RSA_BYTES);done:zero_bytes(digest,sizeof(digest));zero_bytes(expected,sizeof(expected));zero_bytes(observed,sizeof(observed));zero_bytes((u8*)input,sizeof(input));zero_bytes((u8*)output,sizeof(output));return ok;}

static int capture_file_anchor(const char *path,u32 mode,usize limit,struct file_anchor *out){long fd=syscall3(SYS_open,(long)path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0),count;struct kernel_stat before,after;struct sha256_context c;u8 buffer[4096];usize total=0;int ok=0;if(fd<0)return 0;if(syscall2(SYS_fstat,fd,(long)&before)<0||!stat_expected(&before,mode,limit)||!fd_path_is_exact((int)fd,path))goto done;sha_init(&c);while(total<(usize)before.size){usize left=(usize)before.size-total,request=left<sizeof(buffer)?left:sizeof(buffer);count=syscall3(SYS_read,fd,(long)buffer,(long)request);if(count<=0)goto done;sha_update(&c,buffer,(usize)count);total+=(usize)count;}count=syscall3(SYS_read,fd,(long)buffer,1);if(count!=0||syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after))goto done;sha_final(&c,out->digest);copy_bytes((u8*)&out->identity,(const u8*)&after,sizeof(after));ok=1;done:zero_bytes(buffer,sizeof(buffer));if(fd>=0)syscall1(SYS_close,fd);return ok;}
static int hash_file(const char *path,u32 mode,usize limit,u8 out[32]){struct file_anchor anchor;int ok=capture_file_anchor(path,mode,limit,&anchor);if(ok)copy_bytes(out,anchor.digest,32);zero_bytes((u8*)&anchor,sizeof(anchor));return ok;}
static int file_anchor_matches(const char *path,u32 mode,usize limit,const struct file_anchor *expected){struct file_anchor observed;int ok=capture_file_anchor(path,mode,limit,&observed)&&stat_same(&observed.identity,&expected->identity)&&constant_equal(observed.digest,expected->digest,32);zero_bytes((u8*)&observed,sizeof(observed));return ok;}
static int capture_fd_anchor(int fd,u32 mode,usize limit,struct file_anchor *out){long count;struct kernel_stat before,after;struct sha256_context c;u8 buffer[4096];usize total=0;int ok=0;zero_bytes((u8*)&c,sizeof(c));if(fd<0||syscall2(SYS_fstat,fd,(long)&before)<0||!stat_expected(&before,mode,limit))goto done;sha_init(&c);while(total<(usize)before.size){usize left=(usize)before.size-total,request=left<sizeof(buffer)?left:sizeof(buffer);count=syscall4(SYS_pread64,fd,(long)buffer,(long)request,(long)total);if(count<=0)goto done;sha_update(&c,buffer,(usize)count);total+=(usize)count;}count=syscall4(SYS_pread64,fd,(long)buffer,1,(long)total);if(count!=0||syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after))goto done;sha_final(&c,out->digest);copy_bytes((u8*)&out->identity,(const u8*)&after,sizeof(after));ok=1;done:zero_bytes((u8*)&c,sizeof(c));zero_bytes(buffer,sizeof(buffer));return ok;}
static int open_held_file_anchor(const char *path,u32 mode,usize limit,struct file_anchor *out,int *held_fd){long fd=syscall3(SYS_open,(long)path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0);int ok=0;if(fd<0)return 0;if(!fd_path_is_exact((int)fd,path)||!capture_fd_anchor((int)fd,mode,limit,out)||!fd_path_is_exact((int)fd,path))goto done;*held_fd=(int)fd;fd=-1;ok=1;done:if(fd>=0)syscall1(SYS_close,fd);return ok;}
static int open_held_file_anchor_at(int parent_fd,const char *path,u32 mode,usize limit,struct file_anchor *out,int *held_fd){long fd=syscall4(SYS_openat,parent_fd,(long)path_basename(path),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0);int ok=0;if(fd<0)return 0;if(!fd_path_is_exact((int)fd,path)||!capture_fd_anchor((int)fd,mode,limit,out)||!fd_path_is_exact((int)fd,path))goto done;*held_fd=(int)fd;fd=-1;ok=1;done:if(fd>=0)syscall1(SYS_close,fd);return ok;}
static int held_file_anchor_matches(int fd,u32 mode,usize limit,const struct file_anchor *expected){struct file_anchor observed;int ok=capture_fd_anchor(fd,mode,limit,&observed)&&stat_same(&observed.identity,&expected->identity)&&constant_equal(observed.digest,expected->digest,32);zero_bytes((u8*)&observed,sizeof(observed));return ok;}
static int held_regular_identity_matches(int fd,const char *path,const struct kernel_stat *expected){long observed_fd=-1;struct kernel_stat before,observed,after;int ok=0;if(fd<0||!path_is_canonical(path)||syscall2(SYS_fstat,fd,(long)&before)<0||!stat_same(&before,expected)||!fd_path_is_exact(fd,path))goto done;observed_fd=syscall3(SYS_open,(long)path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0);if(observed_fd<0||syscall2(SYS_fstat,observed_fd,(long)&observed)<0||!stat_same(&observed,expected)||!fd_path_is_exact((int)observed_fd,path))goto done;if(syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after)||!stat_same(&after,expected)||!fd_path_is_exact(fd,path))goto done;ok=1;done:if(observed_fd>=0)syscall1(SYS_close,observed_fd);zero_bytes((u8*)&before,sizeof(before));zero_bytes((u8*)&observed,sizeof(observed));zero_bytes((u8*)&after,sizeof(after));return ok;}
static int read_held_anchor_raw(int fd,u32 mode,const struct file_anchor *expected,u8 out[MAX_CAPTURE],usize *outn){long count;struct kernel_stat before,after;u8 digest[32];usize total=0;int ok=0;if(fd<0||syscall2(SYS_fstat,fd,(long)&before)<0||!stat_expected(&before,mode,MAX_CAPTURE)||!stat_same(&before,&expected->identity)||(usize)before.size>MAX_CAPTURE)goto done;while(total<(usize)before.size){count=syscall4(SYS_pread64,fd,(long)(out+total),(long)((usize)before.size-total),(long)total);if(count<=0)goto done;total+=(usize)count;}count=syscall4(SYS_pread64,fd,(long)out,1,(long)total);if(count!=0||syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after))goto done;sha_bytes(out,total,digest);if(!constant_equal(digest,expected->digest,32))goto done;*outn=total;ok=1;done:zero_bytes(digest,sizeof(digest));return ok;}
static int open_held_directory_anchor(const char *path,struct kernel_stat *out,int *held_fd){long fd=syscall3(SYS_open,(long)path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,0);struct kernel_stat before,after;int ok=0;if(fd<0)return 0;if(syscall2(SYS_fstat,fd,(long)&before)<0||!directory_stat_expected(&before)||!fd_path_is_exact((int)fd,path)||syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after)||!fd_path_is_exact((int)fd,path))goto done;copy_bytes((u8*)out,(const u8*)&after,sizeof(after));*held_fd=(int)fd;fd=-1;ok=1;done:if(fd>=0)syscall1(SYS_close,fd);return ok;}
static int held_directory_anchor_matches(int fd,const char *path,const struct kernel_stat *expected){struct kernel_stat before,after;if(fd<0||syscall2(SYS_fstat,fd,(long)&before)<0||!directory_stat_expected(&before)||!stat_same(&before,expected)||!fd_path_is_exact(fd,path)||syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after)||!stat_same(&after,expected)||!fd_path_is_exact(fd,path))return 0;return 1;}
static int directory_path_anchor_matches(const char *path,const struct kernel_stat *expected){long fd=syscall3(SYS_open,(long)path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,0);int ok=0;if(fd>=0)ok=held_directory_anchor_matches((int)fd,path,expected);if(fd>=0)syscall1(SYS_close,fd);return ok;}
static void initialize_python_import_roots(void){usize i;for(i=0;i<MAX_IMPORT_ROOTS;++i)initialize_directory_chain(&held_python_import_roots[i]);}
static void close_python_import_roots(void){usize i;for(i=0;i<EGSI_IMPORT_ROOT_COUNT&&i<MAX_IMPORT_ROOTS;++i)close_directory_chain(&held_python_import_roots[i]);}
static usize python_import_root_metadata_from(const char *path){return path_is_at_or_below(path,"/tmp")?2U:0U;}
static int python_import_root_matches(usize index){usize i;struct kernel_stat observed;const struct python_import_root_entry *expected;struct directory_chain *held;if(index>=EGSI_IMPORT_ROOT_COUNT||index>=MAX_IMPORT_ROOTS)return 0;expected=&python_import_roots[index];held=&held_python_import_roots[index];if(expected->count<2||expected->count>MAX_DIRECTORY_CHAIN||held->count!=expected->count||!string_equal(held->path,expected->path)||held->metadata_from!=python_import_root_metadata_from(held->path)||held->metadata_from>held->count||!directory_chain_matches(held))return 0;for(i=0;i<expected->count;++i){if(syscall2(SYS_fstat,held->fds[i],(long)&observed)<0||!directory_chain_anchor_same(held,i,&observed,&expected->identities[i])){zero_bytes((u8*)&observed,sizeof(observed));return 0;}}zero_bytes((u8*)&observed,sizeof(observed));return 1;}
static int python_import_roots_match(void){usize i;if(EGSI_IMPORT_ROOT_COUNT<3||EGSI_IMPORT_ROOT_COUNT>MAX_IMPORT_ROOTS)return 0;for(i=0;i<EGSI_IMPORT_ROOT_COUNT;++i)if(!python_import_root_matches(i)){diagnostic("Python import root ancestor mismatch: ");diagnostic(python_import_roots[i].path);diagnostic("\n");return 0;}return 1;}
static int open_python_import_roots(void){usize i;initialize_python_import_roots();if(EGSI_IMPORT_ROOT_COUNT<3||EGSI_IMPORT_ROOT_COUNT>MAX_IMPORT_ROOTS)goto fail;for(i=0;i<EGSI_IMPORT_ROOT_COUNT;++i){if(!path_is_canonical(python_import_roots[i].path)||python_import_roots[i].count<2||python_import_roots[i].count>MAX_DIRECTORY_CHAIN||!capture_directory_chain(python_import_roots[i].path,&held_python_import_roots[i]))goto fail;held_python_import_roots[i].metadata_from=python_import_root_metadata_from(python_import_roots[i].path);if(held_python_import_roots[i].metadata_from>held_python_import_roots[i].count||!python_import_root_matches(i))goto fail;}return python_import_roots_match();fail:close_python_import_roots();return 0;}
static void python_runtime_expected_anchor(usize index,struct file_anchor *out){copy_bytes((u8*)&out->identity,(const u8*)&python_runtime_entries[index].identity,sizeof(out->identity));copy_bytes(out->digest,python_runtime_entries[index].digest,32);}
static void initialize_python_runtime(void){usize i;held_python_runtime.parent_count=0;for(i=0;i<MAX_PYTHON_RUNTIME_ENTRIES;++i){held_python_runtime.fds[i]=-1;initialize_directory_chain(&held_python_runtime.parents[i]);}}
static void close_python_runtime(void){usize i;for(i=0;i<EGSI_PYTHON_RUNTIME_ENTRY_COUNT&&i<MAX_PYTHON_RUNTIME_ENTRIES;++i){if(held_python_runtime.fds[i]>=0)syscall1(SYS_close,held_python_runtime.fds[i]);held_python_runtime.fds[i]=-1;}for(i=0;i<held_python_runtime.parent_count&&i<MAX_PYTHON_RUNTIME_ENTRIES;++i)close_directory_chain(&held_python_runtime.parents[i]);held_python_runtime.parent_count=0;}
static int python_runtime_parent_captured(const char *path){usize i;for(i=0;i<held_python_runtime.parent_count;++i)if(string_equal(held_python_runtime.parents[i].path,path))return 1;return 0;}
static int set_python_runtime_chain_policy(struct directory_chain *chain){char work[MAX_PATH];if(system_shared_path(chain->path)){chain->metadata_from=chain->count;return 1;}if(concat2(work,source_root,"/.work")&&path_is_at_or_below(chain->path,work)){usize index=directory_path_index(work);if(index>=chain->count)return 0;chain->metadata_from=index;}else{if(chain->count<2)return 0;chain->metadata_from=chain->count-1;}zero_bytes((u8*)work,sizeof(work));return 1;}
static int python_runtime_preload_plan_valid(void){usize i;u32 previous=0;if(EGSI_PYTHON_RUNTIME_PRELOAD_COUNT<1||EGSI_PYTHON_RUNTIME_PRELOAD_COUNT>=EGSI_PYTHON_RUNTIME_FILE_COUNT)return 0;for(i=0;i<EGSI_PYTHON_RUNTIME_PRELOAD_COUNT;++i){u32 index=python_runtime_preload_indices[i];if(index<1U||index>=EGSI_PYTHON_RUNTIME_FILE_COUNT||(i>0&&index<=previous))return 0;previous=index;}return 1;}
static int python_runtime_matches(void){usize i;struct file_anchor expected;if(EGSI_PYTHON_RUNTIME_ENTRY_COUNT<3||EGSI_PYTHON_RUNTIME_ENTRY_COUNT>MAX_PYTHON_RUNTIME_ENTRIES||EGSI_PYTHON_RUNTIME_FILE_COUNT+1U!=EGSI_PYTHON_RUNTIME_ENTRY_COUNT)return 0;if(!python_runtime_preload_plan_valid()){diagnostic("Python runtime preload plan mismatch\n");return 0;}for(i=0;i<EGSI_PYTHON_RUNTIME_ENTRY_COUNT;++i){python_runtime_expected_anchor(i,&expected);if(held_python_runtime.fds[i]<0||!held_file_anchor_matches(held_python_runtime.fds[i],expected.identity.mode&07777U,MAX_PYTHON_RUNTIME_FILE_BYTES,&expected)||!fd_path_is_exact(held_python_runtime.fds[i],python_runtime_entries[i].path)||!file_anchor_matches(python_runtime_entries[i].path,expected.identity.mode&07777U,MAX_PYTHON_RUNTIME_FILE_BYTES,&expected)){diagnostic("Python runtime file mismatch: ");diagnostic(python_runtime_entries[i].path);diagnostic("\n");zero_bytes((u8*)&expected,sizeof(expected));return 0;}}zero_bytes((u8*)&expected,sizeof(expected));for(i=0;i<held_python_runtime.parent_count;++i)if(!directory_chain_matches(&held_python_runtime.parents[i])){diagnostic("Python runtime directory mismatch: ");diagnostic(held_python_runtime.parents[i].path);diagnostic("\n");return 0;}return 1;}
static int open_python_runtime(void){usize i;char parent[MAX_PATH];struct file_anchor observed,expected;long fd=-1;initialize_python_runtime();if(EGSI_PYTHON_RUNTIME_ENTRY_COUNT<3||EGSI_PYTHON_RUNTIME_ENTRY_COUNT>MAX_PYTHON_RUNTIME_ENTRIES||EGSI_PYTHON_INTERPRETER_INDEX!=0U||EGSI_PYTHON_LOADER_INDEX!=1U||!string_equal(python_runtime_entries[0].path,python_path))goto fail;for(i=0;i<EGSI_PYTHON_RUNTIME_ENTRY_COUNT;++i){const struct python_runtime_contract_entry *entry=&python_runtime_entries[i];if(!path_is_canonical(entry->path)||(entry->identity.mode&0022U)!=0||(entry->identity.mode&S_IFMT)!=S_IFREG||entry->identity.links!=1||entry->identity.size<=0||(usize)entry->identity.size>MAX_PYTHON_RUNTIME_FILE_BYTES)goto fail;fd=syscall3(SYS_open,(long)entry->path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0);if(fd<0||!fd_path_is_exact((int)fd,entry->path)||!capture_fd_anchor((int)fd,entry->identity.mode&07777U,MAX_PYTHON_RUNTIME_FILE_BYTES,&observed))goto fail;python_runtime_expected_anchor(i,&expected);if(!stat_same(&observed.identity,&expected.identity)||!constant_equal(observed.digest,expected.digest,32)||!fd_path_is_exact((int)fd,entry->path))goto fail;held_python_runtime.fds[i]=(int)fd;fd=-1;if(!parent_path(entry->path,parent))goto fail;if(!python_runtime_parent_captured(parent)){if(held_python_runtime.parent_count>=MAX_PYTHON_RUNTIME_ENTRIES||!capture_directory_chain(parent,&held_python_runtime.parents[held_python_runtime.parent_count])||!set_python_runtime_chain_policy(&held_python_runtime.parents[held_python_runtime.parent_count])||!directory_chain_matches(&held_python_runtime.parents[held_python_runtime.parent_count]))goto fail;++held_python_runtime.parent_count;}}zero_bytes((u8*)&observed,sizeof(observed));zero_bytes((u8*)&expected,sizeof(expected));zero_bytes((u8*)parent,sizeof(parent));if(!python_runtime_matches())goto fail;return 1;fail:if(fd>=0)syscall1(SYS_close,fd);zero_bytes((u8*)&observed,sizeof(observed));zero_bytes((u8*)&expected,sizeof(expected));zero_bytes((u8*)parent,sizeof(parent));close_python_runtime();return 0;}
static int python_code_closure_matches(void);
static int append_proc_fd(char *out,usize cap,usize *n,int fd){return append_string(out,cap,n,"/proc/self/fd/")&&append_decimal(out,cap,n,(unsigned long)fd);}
static int python_runtime_exec_prefix(char **child,int capacity,int *count,char loader_fdpath[64],char interpreter_fdpath[64],char preload[MAX_PYTHON_PRELOAD]){usize ln=0,in=0,pn=0,i;if(!python_code_closure_matches()||capacity<7||!python_runtime_preload_plan_valid())return 0;loader_fdpath[0]='\0';interpreter_fdpath[0]='\0';preload[0]='\0';if(!append_proc_fd(loader_fdpath,64,&ln,held_python_runtime.fds[EGSI_PYTHON_LOADER_INDEX])||!append_proc_fd(interpreter_fdpath,64,&in,held_python_runtime.fds[EGSI_PYTHON_INTERPRETER_INDEX]))return 0;for(i=0;i<EGSI_PYTHON_RUNTIME_PRELOAD_COUNT;++i){usize entry_index=(usize)python_runtime_preload_indices[i]+1U;if(i>0&&!append_string(preload,MAX_PYTHON_PRELOAD,&pn,":"))return 0;if(!append_proc_fd(preload,MAX_PYTHON_PRELOAD,&pn,held_python_runtime.fds[entry_index]))return 0;}if(pn==0)return 0;child[(*count)++]=(char*)python_runtime_entries[EGSI_PYTHON_LOADER_INDEX].path;child[(*count)++]="--argv0";child[(*count)++]=(char*)python_path;child[(*count)++]="--preload";child[(*count)++]=preload;child[(*count)++]=interpreter_fdpath;return 1;}
static int inherit_python_runtime(void){usize i;if(!python_runtime_matches())return 0;for(i=0;i<EGSI_PYTHON_RUNTIME_ENTRY_COUNT;++i)if(syscall3(SYS_fcntl,held_python_runtime.fds[i],F_SETFD,0)<0)return 0;return 1;}
static void startup_code_expected_anchor(usize index,struct file_anchor *out){copy_bytes((u8*)&out->identity,(const u8*)&startup_code_files[index].identity,sizeof(out->identity));copy_bytes(out->digest,startup_code_files[index].digest,32);}
static void initialize_python_startup_code(void){usize i;initialize_python_import_roots();for(i=0;i<MAX_STARTUP_CODE_FILES;++i)held_python_startup.file_fds[i]=-1;for(i=0;i<MAX_STARTUP_CODE_DIRECTORIES;++i)held_python_startup.directory_fds[i]=-1;}
static void close_python_startup_code(void){usize i;close_python_import_roots();for(i=0;i<EGSI_STARTUP_CODE_FILE_COUNT&&i<MAX_STARTUP_CODE_FILES;++i){if(held_python_startup.file_fds[i]>=0)syscall1(SYS_close,held_python_startup.file_fds[i]);held_python_startup.file_fds[i]=-1;}for(i=0;i<EGSI_STARTUP_CODE_DIRECTORY_COUNT&&i<MAX_STARTUP_CODE_DIRECTORIES;++i){if(held_python_startup.directory_fds[i]>=0)syscall1(SYS_close,held_python_startup.directory_fds[i]);held_python_startup.directory_fds[i]=-1;}}
static int startup_absent_path_matches(const char *path){struct kernel_stat observed;long result;if(!path_is_canonical(path))return 0;result=syscall4(SYS_newfstatat,AT_FDCWD,(long)path,(long)&observed,AT_SYMLINK_NOFOLLOW);zero_bytes((u8*)&observed,sizeof(observed));return result==-2;}
static int python_startup_code_matches(void){usize i;struct file_anchor expected;if(!python_import_roots_match()||EGSI_STARTUP_CODE_FILE_COUNT<1||EGSI_STARTUP_CODE_FILE_COUNT>MAX_STARTUP_CODE_FILES||EGSI_STARTUP_CODE_DIRECTORY_COUNT<1||EGSI_STARTUP_CODE_DIRECTORY_COUNT>MAX_STARTUP_CODE_DIRECTORIES||EGSI_STARTUP_CODE_ABSENT_COUNT<1||EGSI_STARTUP_CODE_ABSENT_COUNT>MAX_STARTUP_CODE_ABSENT_PATHS||EGSI_STARTUP_CODE_TOTAL_BYTES>64UL*1024UL*1024UL)return 0;for(i=0;i<EGSI_STARTUP_CODE_FILE_COUNT;++i){startup_code_expected_anchor(i,&expected);if(!held_regular_identity_matches(held_python_startup.file_fds[i],startup_code_files[i].path,&expected.identity)){diagnostic("Python startup code file mismatch: ");diagnostic(startup_code_files[i].path);diagnostic("\n");zero_bytes((u8*)&expected,sizeof(expected));return 0;}}zero_bytes((u8*)&expected,sizeof(expected));for(i=0;i<EGSI_STARTUP_CODE_DIRECTORY_COUNT;++i)if(held_python_startup.directory_fds[i]<0||!held_directory_anchor_matches(held_python_startup.directory_fds[i],startup_code_directories[i].path,&startup_code_directories[i].identity)||!directory_path_anchor_matches(startup_code_directories[i].path,&startup_code_directories[i].identity)){diagnostic("Python startup code directory mismatch: ");diagnostic(startup_code_directories[i].path);diagnostic("\n");return 0;}for(i=0;i<EGSI_STARTUP_CODE_ABSENT_COUNT;++i)if(!startup_absent_path_matches(startup_code_absent_paths[i])){diagnostic("Python startup code absent path appeared: ");diagnostic(startup_code_absent_paths[i]);diagnostic("\n");return 0;}return 1;}
static int open_python_startup_code(void){usize i;long fd=-1;struct file_anchor observed,expected;struct kernel_stat directory_observed;initialize_python_startup_code();if(!open_python_import_roots()||EGSI_STARTUP_CODE_FILE_COUNT<1||EGSI_STARTUP_CODE_FILE_COUNT>MAX_STARTUP_CODE_FILES||EGSI_STARTUP_CODE_DIRECTORY_COUNT<1||EGSI_STARTUP_CODE_DIRECTORY_COUNT>MAX_STARTUP_CODE_DIRECTORIES||EGSI_STARTUP_CODE_ABSENT_COUNT<1||EGSI_STARTUP_CODE_ABSENT_COUNT>MAX_STARTUP_CODE_ABSENT_PATHS||EGSI_STARTUP_CODE_TOTAL_BYTES>64UL*1024UL*1024UL)goto fail;for(i=0;i<EGSI_STARTUP_CODE_FILE_COUNT;++i){const struct python_startup_file_entry *entry=&startup_code_files[i];if(!path_is_canonical(entry->path)||(entry->identity.mode&0022U)!=0||(entry->identity.mode&S_IFMT)!=S_IFREG||entry->identity.links!=1||entry->identity.size<0||(usize)entry->identity.size>MAX_STARTUP_CODE_FILE_BYTES)goto fail;fd=syscall3(SYS_open,(long)entry->path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0);if(fd<0||!fd_path_is_exact((int)fd,entry->path)||!capture_fd_anchor((int)fd,entry->identity.mode&07777U,MAX_STARTUP_CODE_FILE_BYTES,&observed))goto fail;startup_code_expected_anchor(i,&expected);if(!stat_same(&observed.identity,&expected.identity)||!constant_equal(observed.digest,expected.digest,32)||!fd_path_is_exact((int)fd,entry->path))goto fail;held_python_startup.file_fds[i]=(int)fd;fd=-1;}for(i=0;i<EGSI_STARTUP_CODE_DIRECTORY_COUNT;++i){const struct python_startup_directory_entry *entry=&startup_code_directories[i];if(!path_is_canonical(entry->path)||(entry->identity.mode&0022U)!=0||(entry->identity.mode&S_IFMT)!=S_IFDIR||entry->identity.links<1)goto fail;if(!open_held_directory_anchor(entry->path,&directory_observed,&held_python_startup.directory_fds[i])||!stat_same(&directory_observed,&entry->identity))goto fail;}for(i=0;i<EGSI_STARTUP_CODE_ABSENT_COUNT;++i)if(!startup_absent_path_matches(startup_code_absent_paths[i]))goto fail;zero_bytes((u8*)&observed,sizeof(observed));zero_bytes((u8*)&expected,sizeof(expected));zero_bytes((u8*)&directory_observed,sizeof(directory_observed));if(!python_startup_code_matches())goto fail;return 1;fail:if(fd>=0)syscall1(SYS_close,fd);zero_bytes((u8*)&observed,sizeof(observed));zero_bytes((u8*)&expected,sizeof(expected));zero_bytes((u8*)&directory_observed,sizeof(directory_observed));close_python_startup_code();return 0;}
static int python_code_closure_matches(void){return python_runtime_matches()&&python_startup_code_matches();}
static int open_pinned_bootstrap(void){long fd=syscall3(SYS_open,(long)bootstrap_path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0),count;struct kernel_stat before,after;struct sha256_context c;u8 digest[32],buffer[4096];usize total=0;int ok=0;if(fd<0)return -1;if(syscall2(SYS_fstat,fd,(long)&before)<0||!stat_expected(&before,EGSI_BOOTSTRAP_MODE,EGSI_BOOTSTRAP_SIZE)||(usize)before.size!=EGSI_BOOTSTRAP_SIZE||!fd_path_is_exact((int)fd,bootstrap_path))goto done;sha_init(&c);while(total<EGSI_BOOTSTRAP_SIZE){usize left=EGSI_BOOTSTRAP_SIZE-total,request=left<sizeof(buffer)?left:sizeof(buffer);count=syscall3(SYS_read,fd,(long)buffer,(long)request);if(count<=0)goto done;sha_update(&c,buffer,(usize)count);total+=(usize)count;}count=syscall3(SYS_read,fd,(long)buffer,1);if(count!=0||syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after))goto done;sha_final(&c,digest);ok=constant_equal(digest,bootstrap_sha256,32);done:zero_bytes(digest,sizeof(digest));zero_bytes(buffer,sizeof(buffer));if(!ok){syscall1(SYS_close,fd);return -1;}return (int)fd;}
static int pinned_bootstrap_path_valid(void){int fd=open_pinned_bootstrap();if(fd<0)return 0;syscall1(SYS_close,fd);return 1;}
static void to_hex(const u8 *v,usize n,char *out){static const char d[]="0123456789abcdef";usize i;for(i=0;i<n;++i){out[i*2]=d[v[i]>>4];out[i*2+1]=d[v[i]&15];}out[n*2]='\0';}
static int from_hex_lower(const char *v,usize n,u8 *out){usize i;if(n%2)return 0;for(i=0;i<n/2;++i){char a=v[i*2],b=v[i*2+1];u8 x,y;if(a>='0'&&a<='9')x=(u8)(a-'0');else if(a>='a'&&a<='f')x=(u8)(a-'a'+10);else return 0;if(b>='0'&&b<='9')y=(u8)(b-'0');else if(b>='a'&&b<='f')y=(u8)(b-'a'+10);else return 0;out[i]=(u8)((x<<4)|y);}return 1;}

#if LAUNCH_KIND == 1 || LAUNCH_KIND == 2 || LAUNCH_KIND == 4
static int tracer_pid_zero(void){long fd=syscall3(SYS_open,(long)proc_self_status,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0),count;char raw[8192];usize n=0,i;int found=0,zero=0;if(fd<0)return 0;while(n<sizeof(raw)-1){count=syscall3(SYS_read,fd,(long)(raw+n),(long)(sizeof(raw)-1-n));if(count<0)goto done;if(count==0)break;n+=(usize)count;}if(n==sizeof(raw)-1){count=syscall3(SYS_read,fd,(long)raw,1);if(count!=0)goto done;}raw[n]='\0';for(i=0;i+10<n;++i){if((i==0||raw[i-1]=='\n')&&raw[i]=='T'&&raw[i+1]=='r'&&raw[i+2]=='a'&&raw[i+3]=='c'&&raw[i+4]=='e'&&raw[i+5]=='r'&&raw[i+6]=='P'&&raw[i+7]=='i'&&raw[i+8]=='d'&&raw[i+9]==':'){usize j=i+10;unsigned long value=0;while(j<n&&(raw[j]==' '||raw[j]=='\t'))++j;if(j>=n||raw[j]<'0'||raw[j]>'9')goto done;while(j<n&&raw[j]>='0'&&raw[j]<='9'){if(value>1000000UL)goto done;value=value*10+(unsigned long)(raw[j]-'0');++j;}if(j>=n||raw[j]!='\n')goto done;found=1;zero=value==0;break;}}done:zero_bytes((u8*)raw,sizeof(raw));syscall1(SYS_close,fd);return found&&zero;}
static int harden_signer(void){struct kernel_rlimit limit;limit.current=0;limit.maximum=0;if(syscall5(SYS_prctl,PR_SET_DUMPABLE,0,0,0,0)!=0)return 0;if(syscall2(SYS_setrlimit,RLIMIT_CORE,(long)&limit)!=0)return 0;if(syscall1(SYS_prctl,PR_GET_DUMPABLE)!=0)return 0;if(syscall2(SYS_getrlimit,RLIMIT_CORE,(long)&limit)!=0||limit.current!=0||limit.maximum!=0)return 0;return tracer_pid_zero();}
static int signer_security_state(void){struct kernel_rlimit limit;if(syscall1(SYS_prctl,PR_GET_DUMPABLE)!=0||syscall2(SYS_getrlimit,RLIMIT_CORE,(long)&limit)!=0||limit.current!=0||limit.maximum!=0||!tracer_pid_zero())return 0;write_text(1,"EGSI_NATIVE_DUMPABLE=0\nEGSI_NATIVE_TRACER_PID=0\nEGSI_NATIVE_CORE_SOFT=0\nEGSI_NATIVE_CORE_HARD=0\n");return 1;}
#endif

static int public_contract(void){char kh[65],bh[65],ch[65],sh[65],ph[65],rh[65],sch[65],out[2048];usize n=0;to_hex(native_key_id,32,kh);to_hex(native_build_id,32,bh);to_hex(native_contract_value,32,ch);to_hex(bootstrap_sha256,32,sh);to_hex(python_sha256,32,ph);to_hex(python_runtime_closure,32,rh);to_hex(startup_code_closure,32,sch);out[0]='\0';if(!append_string(out,sizeof(out),&n,"EGSI_NATIVE_ATTESTATION_VERSION=2\nEGSI_NATIVE_ALGORITHM=")||!append_string(out,sizeof(out),&n,algorithm)||!append_string(out,sizeof(out),&n,"\nEGSI_NATIVE_PUBLIC_KEY_ID=sha256:")||!append_string(out,sizeof(out),&n,kh)||!append_string(out,sizeof(out),&n,"\nEGSI_NATIVE_BUILD_ID=sha256:")||!append_string(out,sizeof(out),&n,bh)||!append_string(out,sizeof(out),&n,"\nEGSI_NATIVE_BINARY_CONTRACT=sha256:")||!append_string(out,sizeof(out),&n,ch)||!append_string(out,sizeof(out),&n,"\nEGSI_BOOTSTRAP_PATH=")||!append_string(out,sizeof(out),&n,bootstrap_path)||!append_string(out,sizeof(out),&n,"\nEGSI_BOOTSTRAP_SHA256=sha256:")||!append_string(out,sizeof(out),&n,sh)||!append_string(out,sizeof(out),&n,"\nEGSI_BOOTSTRAP_SIZE=")||!append_decimal(out,sizeof(out),&n,EGSI_BOOTSTRAP_SIZE)||!append_string(out,sizeof(out),&n,"\nEGSI_BOOTSTRAP_MODE=")||!append_octal4(out,sizeof(out),&n,EGSI_BOOTSTRAP_MODE)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_PATH=")||!append_string(out,sizeof(out),&n,python_path)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_SHA256=sha256:")||!append_string(out,sizeof(out),&n,ph)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_SIZE=")||!append_decimal(out,sizeof(out),&n,EGSI_PYTHON_SIZE)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_MODE=")||!append_octal4(out,sizeof(out),&n,EGSI_PYTHON_MODE)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_DEVICE=")||!append_decimal(out,sizeof(out),&n,EGSI_PYTHON_DEVICE)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_INODE=")||!append_decimal(out,sizeof(out),&n,EGSI_PYTHON_INODE)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_RUNTIME_CLOSURE=sha256:")||!append_string(out,sizeof(out),&n,rh)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_RUNTIME_FILE_COUNT=")||!append_decimal(out,sizeof(out),&n,EGSI_PYTHON_RUNTIME_FILE_COUNT)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_STARTUP_CODE_CLOSURE=sha256:")||!append_string(out,sizeof(out),&n,sch)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_STARTUP_CODE_FILE_COUNT=")||!append_decimal(out,sizeof(out),&n,EGSI_STARTUP_CODE_FILE_COUNT)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_STARTUP_CODE_DIRECTORY_COUNT=")||!append_decimal(out,sizeof(out),&n,EGSI_STARTUP_CODE_DIRECTORY_COUNT)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_STARTUP_CODE_ABSENT_COUNT=")||!append_decimal(out,sizeof(out),&n,EGSI_STARTUP_CODE_ABSENT_COUNT)||!append_string(out,sizeof(out),&n,"\nEGSI_PYTHON_STARTUP_CODE_TOTAL_BYTES=")||!append_decimal(out,sizeof(out),&n,EGSI_STARTUP_CODE_TOTAL_BYTES)||!append_string(out,sizeof(out),&n,"\n"))return 0;write_text(1,out);return 1;}

struct invocation{
    const char *name,*output,*output_root,*case_id,*focused,*full,*report,*case_file,*scope_file,*provider_config,*attestation;
    char run_id[65],nonce[65],realtime_start[32],monotonic_start[32];
    char focused_path[MAX_PATH],full_path[MAX_PATH],focused_sidecar[MAX_PATH],full_sidecar[MAX_PATH];
    char preflight_path[MAX_PATH],candidate_path[MAX_PATH],snapshot_path[MAX_PATH],attestation_sidecar[MAX_PATH],attestation_parent[MAX_PATH];
    char receipt_parent[MAX_PATH],config_parent[MAX_PATH],bootstrap_parent[MAX_PATH],runtime_parent[MAX_PATH];
    char bootstrap_hash[72],focused_hash[72],focused_sidecar_hash[72],full_hash[72],full_sidecar_hash[72];
    char pre_inventory_hash[72],post_inventory_hash[72],runner_lock_hash[72],project_identity_hash[72];
    char canonical_contract_hash[72],native_launcher_contract_hash[72],native_binary_contract_hash[72],public_key_hash[72];
    char candidate_attestation_hash[72],candidate_commitment_hash[72],semantic_snapshot_hash[72];
    u8 candidate_file_hash[32],candidate_artifact_file_hash[32];
    struct file_anchor live_artifact_anchor,live_sidecar_anchor,candidate_artifact_anchor,candidate_envelope_anchor,semantic_snapshot_anchor;
    struct kernel_stat live_parent_anchor;
    struct directory_chain source_chain,config_chain,bootstrap_chain,runtime_chain,receipt_chain,live_chain;
    int live_artifact_fd,live_sidecar_fd,live_parent_fd,candidate_artifact_fd,candidate_envelope_fd,semantic_snapshot_fd;
    int help,public_mode,security_mode;
};
static int receipt_arguments(int argc,char **argv,struct invocation *v){int i=1,nc=0,oc=0;if(argc==2&&string_equal(argv[1],"--help")){v->help=1;return 1;}if(argc==2&&string_equal(argv[1],"--native-public-contract")){v->public_mode=1;return 1;}if(argc==2&&string_equal(argv[1],"--native-security-state")){v->security_mode=1;return 1;}while(i<argc){if(string_equal(argv[i],"--name")){if(++nc!=1||i+1>=argc||!(string_equal(argv[i+1],"focused")||string_equal(argv[i+1],"full")))return 0;v->name=argv[i+1];i+=2;}else if(string_equal(argv[i],"--output")){if(++oc!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->output=argv[i+1];i+=2;}else return 0;}return nc==1&&oc==1;}
static int gate_arguments(int argc,char **argv,struct invocation *v){int i=1,orc=0,cc=0,fc=0,uc=0,rc=0,op=0;char expected[MAX_PATH];if(argc==2&&string_equal(argv[1],"--help")){v->help=1;return 1;}if(argc==2&&string_equal(argv[1],"--native-public-contract")){v->public_mode=1;return 1;}while(i<argc){
#if LAUNCH_KIND == 2
    if(argc==2&&string_equal(argv[1],"--native-security-state")){v->security_mode=1;return 1;}
    if(string_equal(argv[i],"--rerun-tests")){if(++op!=1)return 0;++i;}
#else
    if(string_equal(argv[i],"--mode")){if(++op!=1||i+1>=argc||!string_equal(argv[i+1],"verify-only"))return 0;i+=2;}
#endif
    else if(string_equal(argv[i],"--case-id")){if(++cc!=1||i+1>=argc||!is_value(argv[i+1]))return 0;v->case_id=argv[i+1];i+=2;}else if(string_equal(argv[i],"--output-root")){if(++orc!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->output_root=argv[i+1];i+=2;}else if(string_equal(argv[i],"--focused-receipt")){if(++fc!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->focused=argv[i+1];i+=2;}else if(string_equal(argv[i],"--full-receipt")){if(++uc!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->full=argv[i+1];i+=2;}else if(string_equal(argv[i],"--report")){if(++rc!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->report=argv[i+1];i+=2;}else return 0;}if(!(orc==1&&cc==1&&fc==1&&uc==1&&rc==1&&op==1))return 0;if(!concat2(expected,v->output_root,"/reports/offline-focused-receipt.json")||!string_equal(expected,v->focused))return 0;if(!concat2(expected,v->output_root,"/reports/offline-full-receipt.json")||!string_equal(expected,v->full))return 0;if(!concat2(expected,v->output_root,"/reports/first-case-hard-gate.json")||!string_equal(expected,v->report))return 0;return 1;}

static int live_arguments(int argc,char **argv,struct invocation *v){int i=1,orc=0,cfc=0,sfc=0,pcc=0,ac=0,op=0;char expected[MAX_PATH];if(argc==2&&string_equal(argv[1],"--help")){v->help=1;return 1;}if(argc==2&&string_equal(argv[1],"--native-public-contract")){v->public_mode=1;return 1;}
#if LAUNCH_KIND == 4
if(argc==2&&string_equal(argv[1],"--native-security-state")){v->security_mode=1;return 1;}
#endif
while(i<argc){if(string_equal(argv[i],"--output-root")){if(++orc!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->output_root=argv[i+1];i+=2;}else if(string_equal(argv[i],"--case-file")){if(++cfc!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->case_file=argv[i+1];i+=2;}else if(string_equal(argv[i],"--scope-case-file")){if(++sfc!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->scope_file=argv[i+1];i+=2;}else if(string_equal(argv[i],"--attestation")){if(++ac!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->attestation=argv[i+1];i+=2;}
#if LAUNCH_KIND == 4
else if(string_equal(argv[i],"--provider-config")){if(++pcc!=1||i+1>=argc||!path_is_canonical(argv[i+1]))return 0;v->provider_config=argv[i+1];i+=2;}
#else
else if(string_equal(argv[i],"--mode")){if(++op!=1||i+1>=argc||!string_equal(argv[i+1],"verify-only"))return 0;i+=2;}
#endif
else return 0;}if(!(orc==1&&cfc==1&&sfc==1&&ac==1))return 0;
#if LAUNCH_KIND == 4
if(pcc!=1)return 0;
#else
if(op!=1)return 0;
#endif
if(!concat2(expected,source_root,"/configs/recover_3wfj_cases.txt")||!string_equal(expected,v->case_file))return 0;if(!concat2(expected,source_root,"/configs/p0_cases.txt")||!string_equal(expected,v->scope_file))return 0;if(!concat2(expected,v->output_root,"/reports/remaining-p0/fail-fast-live-attestation.json")||!string_equal(expected,v->attestation))return 0;
#if LAUNCH_KIND == 4
if(!concat2(expected,source_root,"/configs/providers.local.toml")||!string_equal(expected,v->provider_config))return 0;
#endif
return 1;}

static int prepare_live_invocation(struct invocation *v){u8 random[64];struct kernel_timespec rt,mono;usize n=0;long got=syscall3(SYS_getrandom,(long)random,sizeof(random),0);if(got!=(long)sizeof(random))return 0;to_hex(random,32,v->run_id);to_hex(random+32,32,v->nonce);if(syscall2(SYS_clock_gettime,CLOCK_REALTIME,(long)&rt)<0||syscall2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&mono)<0||rt.seconds<0||rt.nanoseconds<0||mono.seconds<0||mono.nanoseconds<0)return 0;v->realtime_start[0]='\0';v->monotonic_start[0]='\0';if(!append_decimal(v->realtime_start,sizeof(v->realtime_start),&n,(unsigned long)rt.seconds*1000000000UL+(unsigned long)rt.nanoseconds))return 0;n=0;if(!append_decimal(v->monotonic_start,sizeof(v->monotonic_start),&n,(unsigned long)mono.seconds*1000000000UL+(unsigned long)mono.nanoseconds))return 0;zero_bytes(random,sizeof(random));return 1;}

static int verify_attestation(const char *artifact,const char *domain,const char *name);
static void digest_text(const u8 digest[32],char out[72]){usize n=0;out[0]='\0';append_string(out,72,&n,"sha256:");to_hex(digest,32,out+n);}
static int hash_path_text(const char *path,u32 mode,usize limit,char out[72]){u8 digest[32];if(!hash_file(path,mode,limit,digest))return 0;digest_text(digest,out);zero_bytes(digest,sizeof(digest));return 1;}
static int prepare_live_paths(struct invocation *v){char observed_parent[MAX_PATH];if(!concat2(v->focused_path,v->output_root,"/reports/offline-focused-receipt.json")||!concat2(v->full_path,v->output_root,"/reports/offline-full-receipt.json")||!concat2(v->focused_sidecar,v->focused_path,sidecar_suffix)||!concat2(v->full_sidecar,v->full_path,sidecar_suffix)||!concat2(v->attestation_sidecar,v->attestation,sidecar_suffix)||!concat2(v->preflight_path,v->attestation,".native-preflight")||!concat2(v->candidate_path,v->attestation,".native-candidate")||!concat2(v->snapshot_path,v->attestation,".native-snapshot")||!parent_path(v->attestation,v->attestation_parent)||!parent_path(v->attestation_sidecar,observed_parent)||!string_equal(v->attestation_parent,observed_parent)||!parent_path(v->preflight_path,observed_parent)||!string_equal(v->attestation_parent,observed_parent)||!parent_path(v->candidate_path,observed_parent)||!string_equal(v->attestation_parent,observed_parent)||!parent_path(v->snapshot_path,observed_parent)||!string_equal(v->attestation_parent,observed_parent)||!parent_path(v->focused_path,v->receipt_parent)||!parent_path(v->full_path,observed_parent)||!string_equal(v->receipt_parent,observed_parent)||!parent_path(v->focused_sidecar,observed_parent)||!string_equal(v->receipt_parent,observed_parent)||!parent_path(v->full_sidecar,observed_parent)||!string_equal(v->receipt_parent,observed_parent)||!parent_path(v->case_file,v->config_parent)||!parent_path(v->scope_file,observed_parent)||!string_equal(v->config_parent,observed_parent)||!parent_path(bootstrap_path,v->bootstrap_parent)||!parent_path(python_path,v->runtime_parent))return 0;
#if LAUNCH_KIND == 4
if(!parent_path(v->provider_config,observed_parent)||!string_equal(v->config_parent,observed_parent))return 0;
#endif
return 1;}
#if LAUNCH_KIND == 4 || LAUNCH_KIND == 5
static void initialize_live_directory_chains(struct invocation *v){initialize_directory_chain(&v->source_chain);initialize_directory_chain(&v->config_chain);initialize_directory_chain(&v->bootstrap_chain);initialize_directory_chain(&v->runtime_chain);initialize_directory_chain(&v->receipt_chain);initialize_directory_chain(&v->live_chain);}
static void close_live_directory_chains(struct invocation *v){close_directory_chain(&v->live_chain);close_directory_chain(&v->receipt_chain);close_directory_chain(&v->runtime_chain);close_directory_chain(&v->bootstrap_chain);close_directory_chain(&v->config_chain);close_directory_chain(&v->source_chain);}
static int capture_live_base_directory_chains(struct invocation *v){if(!capture_directory_chain(source_root,&v->source_chain)){diagnostic("native source directory-chain capture failed\n");goto fail;}if(!capture_directory_chain(v->config_parent,&v->config_chain)){diagnostic("native config directory-chain capture failed\n");goto fail;}if(!capture_directory_chain(v->bootstrap_parent,&v->bootstrap_chain)){diagnostic("native bootstrap directory-chain capture failed\n");goto fail;}if(!capture_directory_chain(v->runtime_parent,&v->runtime_chain)){diagnostic("native runtime directory-chain capture failed\n");goto fail;}if(!capture_directory_chain(v->receipt_parent,&v->receipt_chain)){diagnostic("native receipt directory-chain capture failed\n");goto fail;}return 1;fail:close_live_directory_chains(v);return 0;}
static int live_base_directory_chains_match(const struct invocation *v){return directory_chain_matches(&v->source_chain)&&directory_chain_matches(&v->config_chain)&&directory_chain_matches(&v->bootstrap_chain)&&directory_chain_matches(&v->runtime_chain)&&directory_chain_matches(&v->receipt_chain);}
static int capture_live_parent_directory_chain(struct invocation *v){close_directory_chain(&v->live_chain);return capture_directory_chain(v->attestation_parent,&v->live_chain)&&directory_chain_matches(&v->live_chain);}
static int live_directory_chains_match(const struct invocation *v){return live_base_directory_chains_match(v)&&directory_chain_matches(&v->live_chain);}
#endif
#if LAUNCH_KIND == 4 || LAUNCH_KIND == 5
static int capture_live_receipt_anchors(struct invocation *v){digest_text(bootstrap_sha256,v->bootstrap_hash);digest_text(native_contract_value,v->native_binary_contract_hash);digest_text(native_key_id,v->public_key_hash);if(!live_base_directory_chains_match(v)||!verify_attestation(v->focused_path,focused_domain,focused_basename)||!verify_attestation(v->full_path,full_domain,full_basename)||!hash_path_text(v->focused_path,0600,MAX_ARTIFACT_BYTES,v->focused_hash)||!hash_path_text(v->focused_sidecar,0600,MAX_CAPTURE,v->focused_sidecar_hash)||!hash_path_text(v->full_path,0600,MAX_ARTIFACT_BYTES,v->full_hash)||!hash_path_text(v->full_sidecar,0600,MAX_CAPTURE,v->full_sidecar_hash)||!live_base_directory_chains_match(v))return 0;return 1;}
static int verify_live_receipt_anchors(const struct invocation *v){char observed[72];return live_base_directory_chains_match(v)&&pinned_bootstrap_path_valid()&&verify_attestation(v->focused_path,focused_domain,focused_basename)&&verify_attestation(v->full_path,full_domain,full_basename)&&hash_path_text(v->focused_path,0600,MAX_ARTIFACT_BYTES,observed)&&string_equal(observed,v->focused_hash)&&hash_path_text(v->focused_sidecar,0600,MAX_CAPTURE,observed)&&string_equal(observed,v->focused_sidecar_hash)&&hash_path_text(v->full_path,0600,MAX_ARTIFACT_BYTES,observed)&&string_equal(observed,v->full_hash)&&hash_path_text(v->full_sidecar,0600,MAX_CAPTURE,observed)&&string_equal(observed,v->full_sidecar_hash)&&live_base_directory_chains_match(v);}
#endif
#if LAUNCH_KIND == 5
static int verify_held_live_artifact_anchors(const struct invocation *v);
static void close_live_artifact_fds(struct invocation *v){if(v->live_artifact_fd>=0){syscall1(SYS_close,v->live_artifact_fd);v->live_artifact_fd=-1;}if(v->live_sidecar_fd>=0){syscall1(SYS_close,v->live_sidecar_fd);v->live_sidecar_fd=-1;}if(v->semantic_snapshot_fd>=0){syscall1(SYS_close,v->semantic_snapshot_fd);v->semantic_snapshot_fd=-1;}close_directory_chain(&v->live_chain);}
static int live_artifact_paths_match(const struct invocation *v){return live_directory_chains_match(v)&&file_anchor_matches(v->attestation,0600,MAX_ARTIFACT_BYTES,&v->live_artifact_anchor)&&file_anchor_matches(v->attestation_sidecar,0600,MAX_CAPTURE,&v->live_sidecar_anchor)&&held_file_anchor_matches(v->semantic_snapshot_fd,0600,MAX_ARTIFACT_BYTES,&v->semantic_snapshot_anchor)&&file_anchor_matches(v->snapshot_path,0600,MAX_ARTIFACT_BYTES,&v->semantic_snapshot_anchor);}
static int capture_live_artifact_anchors(struct invocation *v){int parent_fd;close_live_artifact_fds(v);if(!capture_live_parent_directory_chain(v)||(parent_fd=directory_chain_leaf_fd(&v->live_chain))<0||!open_held_file_anchor_at(parent_fd,v->attestation,0600,MAX_ARTIFACT_BYTES,&v->live_artifact_anchor,&v->live_artifact_fd)||!open_held_file_anchor_at(parent_fd,v->attestation_sidecar,0600,MAX_CAPTURE,&v->live_sidecar_anchor,&v->live_sidecar_fd)||!open_held_file_anchor_at(parent_fd,v->snapshot_path,0600,MAX_ARTIFACT_BYTES,&v->semantic_snapshot_anchor,&v->semantic_snapshot_fd)||!verify_held_live_artifact_anchors(v)||!live_artifact_paths_match(v)){close_live_artifact_fds(v);return 0;}return 1;}
static int verify_live_artifact_anchors(const struct invocation *v){return live_artifact_paths_match(v)&&verify_held_live_artifact_anchors(v)&&live_artifact_paths_match(v);}
#endif
static int remove_path(const char *path){long r=syscall1(SYS_unlink,(long)path);return r==0||r==-2;}
static int read_regular_raw(const char *path,u32 mode,u8 out[MAX_CAPTURE],usize *outn){long fd=syscall3(SYS_open,(long)path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0),count;struct kernel_stat before,after;usize total=0;int ok=0;if(fd<0)return 0;if(syscall2(SYS_fstat,fd,(long)&before)<0||!stat_expected(&before,mode,MAX_CAPTURE)||before.size<=0||!fd_path_is_exact((int)fd,path))goto done;while(total<(usize)before.size){count=syscall3(SYS_read,fd,(long)(out+total),(long)((usize)before.size-total));if(count<=0)goto done;total+=(usize)count;}count=syscall3(SYS_read,fd,(long)out,1);if(count!=0||syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after))goto done;*outn=total;ok=1;done:if(fd>=0)syscall1(SYS_close,fd);return ok;}
static int consume_literal(const u8 *raw,usize total,usize *offset,const char *literal){usize n=string_length(literal);if(*offset+n>total||!constant_equal(raw+*offset,(const u8*)literal,n))return 0;*offset+=n;return 1;}
static int consume_exact_line(const u8 *raw,usize total,usize *offset,const char *name,const char *value){return consume_literal(raw,total,offset,name)&&consume_literal(raw,total,offset,"=")&&consume_literal(raw,total,offset,value)&&consume_literal(raw,total,offset,"\n");}
static int consume_hash_line(const u8 *raw,usize total,usize *offset,const char *name,char out[72]){usize i;if(!consume_literal(raw,total,offset,name)||!consume_literal(raw,total,offset,"=sha256:"))return 0;if(*offset+65>total)return 0;out[0]='s';out[1]='h';out[2]='a';out[3]='2';out[4]='5';out[5]='6';out[6]=':';for(i=0;i<64;++i){char c=(char)raw[*offset+i];if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return 0;out[7+i]=c;}out[71]='\0';*offset+=64;if(raw[*offset]!='\n')return 0;*offset+=1;return 1;}
static int consume_expected_hash_line(const u8 *raw,usize total,usize *offset,const char *name,const char *expected){char observed[72];return consume_hash_line(raw,total,offset,name,observed)&&string_equal(observed,expected);}

static int run_child(int argc,char **argv,struct invocation *v){
    char *child[MAX_USER_ARGS+80],loader_fdpath[64],interpreter_fdpath[64],preload[MAX_PYTHON_PRELOAD],bootstrap_fdpath[64],attestation_fdpath[64],snapshot_fdpath[64],attestation_fd_text[32],sidecar_fd_text[32],snapshot_fd_text[32];
    char *env[]={env_path,env_lang,env_lc_all,env_tz,env_home,env_tmpdir,env_no_bytecode,env_no_plugins,(char*)0};
    usize fn=0,an=0,sn=0,afn=0,sfn=0,ssfn=0;int n=0,i,status=0,bootstrap_fd=open_pinned_bootstrap();long pid;
    if(bootstrap_fd<0||!python_code_closure_matches()){if(bootstrap_fd>=0)syscall1(SYS_close,bootstrap_fd);return 126;}
    bootstrap_fdpath[0]='\0';attestation_fdpath[0]='\0';snapshot_fdpath[0]='\0';attestation_fd_text[0]='\0';sidecar_fd_text[0]='\0';snapshot_fd_text[0]='\0';
    if(!append_string(bootstrap_fdpath,sizeof(bootstrap_fdpath),&fn,"/proc/self/fd/")||!append_decimal(bootstrap_fdpath,sizeof(bootstrap_fdpath),&fn,(unsigned long)bootstrap_fd)){syscall1(SYS_close,bootstrap_fd);return 126;}
#if LAUNCH_KIND == 5
    if(!v->help&&(v->live_artifact_fd<0||v->live_sidecar_fd<0||v->semantic_snapshot_fd<0||!append_string(attestation_fdpath,sizeof(attestation_fdpath),&an,"/proc/self/fd/")||!append_decimal(attestation_fdpath,sizeof(attestation_fdpath),&an,(unsigned long)v->live_artifact_fd)||!append_string(snapshot_fdpath,sizeof(snapshot_fdpath),&sn,"/proc/self/fd/")||!append_decimal(snapshot_fdpath,sizeof(snapshot_fdpath),&sn,(unsigned long)v->semantic_snapshot_fd)||!append_decimal(attestation_fd_text,sizeof(attestation_fd_text),&afn,(unsigned long)v->live_artifact_fd)||!append_decimal(sidecar_fd_text,sizeof(sidecar_fd_text),&sfn,(unsigned long)v->live_sidecar_fd)||!append_decimal(snapshot_fd_text,sizeof(snapshot_fd_text),&ssfn,(unsigned long)v->semantic_snapshot_fd))){syscall1(SYS_close,bootstrap_fd);return 126;}
#endif
    if(!python_runtime_exec_prefix(child,MAX_USER_ARGS+80,&n,loader_fdpath,interpreter_fdpath,preload)){syscall1(SYS_close,bootstrap_fd);return 126;}child[n++]="-X";child[n++]=(char*)startup_pycache_option;child[n++]="-I";child[n++]="-B";child[n++]="-S";child[n++]=bootstrap_fdpath;child[n++]=(char*)bootstrap_mode;child[n++]="--root";child[n++]=(char*)source_root;child[n++]="--";
    for(i=1;i<argc;++i){
#if LAUNCH_KIND == 5
        if(!v->help&&string_equal(argv[i],"--attestation")&&i+1<argc){child[n++]=argv[i];child[n++]=attestation_fdpath;++i;continue;}
#endif
        child[n++]=argv[i];
    }
#if LAUNCH_KIND == 4
if(!v->help){child[n++]="--native-run-id";child[n++]=v->run_id;child[n++]="--native-nonce";child[n++]=v->nonce;child[n++]="--native-realtime-start-ns";child[n++]=v->realtime_start;child[n++]="--native-monotonic-start-ns";child[n++]=v->monotonic_start;child[n++]="--native-candidate-envelope";child[n++]=v->candidate_path;child[n++]="--native-pre-inventory-sha256";child[n++]=v->pre_inventory_hash;child[n++]="--native-bootstrap-sha256";child[n++]=v->bootstrap_hash;child[n++]="--native-focused-receipt-sha256";child[n++]=v->focused_hash;child[n++]="--native-focused-sidecar-sha256";child[n++]=v->focused_sidecar_hash;child[n++]="--native-full-receipt-sha256";child[n++]=v->full_hash;child[n++]="--native-full-sidecar-sha256";child[n++]=v->full_sidecar_hash;child[n++]="--native-runner-lock-sha256";child[n++]=v->runner_lock_hash;child[n++]="--native-project-identity-sha256";child[n++]=v->project_identity_hash;child[n++]="--native-canonical-test-contract-sha256";child[n++]=v->canonical_contract_hash;child[n++]="--native-launcher-contract-sha256";child[n++]=v->native_launcher_contract_hash;child[n++]="--native-binary-contract-sha256";child[n++]=v->native_binary_contract_hash;child[n++]="--native-public-key-id";child[n++]=v->public_key_hash;}
#elif LAUNCH_KIND == 5
if(!v->help){child[n++]="--native-bootstrap-sha256";child[n++]=v->bootstrap_hash;child[n++]="--native-focused-receipt-sha256";child[n++]=v->focused_hash;child[n++]="--native-focused-sidecar-sha256";child[n++]=v->focused_sidecar_hash;child[n++]="--native-full-receipt-sha256";child[n++]=v->full_hash;child[n++]="--native-full-sidecar-sha256";child[n++]=v->full_sidecar_hash;child[n++]="--native-binary-contract-sha256";child[n++]=v->native_binary_contract_hash;child[n++]="--native-public-key-id";child[n++]=v->public_key_hash;child[n++]="--native-attestation-path";child[n++]=(char*)v->attestation;child[n++]="--native-attestation-fd";child[n++]=attestation_fd_text;child[n++]="--native-attestation-sidecar-fd";child[n++]=sidecar_fd_text;child[n++]="--native-semantic-snapshot";child[n++]=snapshot_fdpath;child[n++]="--native-semantic-snapshot-path";child[n++]=v->snapshot_path;child[n++]="--native-semantic-snapshot-fd";child[n++]=snapshot_fd_text;}
#endif
    child[n]=(char*)0;pid=syscall0(SYS_fork);if(pid<0){syscall1(SYS_close,bootstrap_fd);return 126;}if(pid==0){
        if(!python_code_closure_matches()||!inherit_python_runtime()||syscall3(SYS_fcntl,bootstrap_fd,F_SETFD,0)<0
#if LAUNCH_KIND == 5
        ||(!v->help&&(syscall3(SYS_fcntl,v->live_artifact_fd,F_SETFD,0)<0||syscall3(SYS_fcntl,v->live_sidecar_fd,F_SETFD,0)<0||syscall3(SYS_fcntl,v->semantic_snapshot_fd,F_SETFD,0)<0))
#endif
        ){write_text(2,"locked child descriptor setup failed\n");syscall1(SYS_exit,126);}syscall3(SYS_execve,(long)loader_fdpath,(long)child,(long)env);write_text(2,"locked launcher execve failed\n");syscall1(SYS_exit,126);for(;;){}
    }
    syscall1(SYS_close,bootstrap_fd);if(syscall4(SYS_wait4,pid,(long)&status,0,0)<0){diagnostic("locked launcher wait failed\n");return 126;}if(!pinned_bootstrap_path_valid()){diagnostic("locked bootstrap changed after child\n");return 126;}if(!python_code_closure_matches()){diagnostic("locked Python code closure changed after child\n");return 126;}if((status&0x7f)==0){int code=(status>>8)&0xff;if(code==126)diagnostic("locked Python child exited 126\n");return code;}return 128+(status&0x7f);
}

#if LAUNCH_KIND == 4
static void close_live_candidate_fds(struct invocation *v){if(v->candidate_artifact_fd>=0){syscall1(SYS_close,v->candidate_artifact_fd);v->candidate_artifact_fd=-1;}if(v->candidate_envelope_fd>=0){syscall1(SYS_close,v->candidate_envelope_fd);v->candidate_envelope_fd=-1;}if(v->semantic_snapshot_fd>=0){syscall1(SYS_close,v->semantic_snapshot_fd);v->semantic_snapshot_fd=-1;}close_directory_chain(&v->live_chain);}
static int semantic_snapshot_anchor_hash_matches(const struct invocation *v){char observed[72];digest_text(v->semantic_snapshot_anchor.digest,observed);return string_equal(observed,v->semantic_snapshot_hash);}
static int live_candidate_paths_match(const struct invocation *v){return live_directory_chains_match(v)&&held_file_anchor_matches(v->candidate_artifact_fd,0600,MAX_ARTIFACT_BYTES,&v->candidate_artifact_anchor)&&held_file_anchor_matches(v->candidate_envelope_fd,0600,MAX_CAPTURE,&v->candidate_envelope_anchor)&&held_file_anchor_matches(v->semantic_snapshot_fd,0600,MAX_ARTIFACT_BYTES,&v->semantic_snapshot_anchor)&&file_anchor_matches(v->attestation,0600,MAX_ARTIFACT_BYTES,&v->candidate_artifact_anchor)&&file_anchor_matches(v->candidate_path,0600,MAX_CAPTURE,&v->candidate_envelope_anchor)&&file_anchor_matches(v->snapshot_path,0600,MAX_ARTIFACT_BYTES,&v->semantic_snapshot_anchor)&&semantic_snapshot_anchor_hash_matches(v);}
static int capture_live_candidate_anchors(struct invocation *v){int parent_fd;close_live_candidate_fds(v);if(!capture_live_parent_directory_chain(v)||(parent_fd=directory_chain_leaf_fd(&v->live_chain))<0||!open_held_file_anchor_at(parent_fd,v->attestation,0600,MAX_ARTIFACT_BYTES,&v->candidate_artifact_anchor,&v->candidate_artifact_fd)||!open_held_file_anchor_at(parent_fd,v->candidate_path,0600,MAX_CAPTURE,&v->candidate_envelope_anchor,&v->candidate_envelope_fd)||!open_held_file_anchor_at(parent_fd,v->snapshot_path,0600,MAX_ARTIFACT_BYTES,&v->semantic_snapshot_anchor,&v->semantic_snapshot_fd)||!constant_equal(v->candidate_artifact_anchor.digest,v->candidate_artifact_file_hash,32)||!constant_equal(v->candidate_envelope_anchor.digest,v->candidate_file_hash,32)||!live_candidate_paths_match(v)){close_live_candidate_fds(v);return 0;}return 1;}
static int verify_live_candidate_anchors(const struct invocation *v){return live_candidate_paths_match(v)&&constant_equal(v->candidate_artifact_anchor.digest,v->candidate_artifact_file_hash,32)&&constant_equal(v->candidate_envelope_anchor.digest,v->candidate_file_hash,32)&&live_candidate_paths_match(v);}
static int verify_published_live_candidate(const struct invocation *v){return verify_live_candidate_anchors(v)&&verify_attestation(v->attestation,live_domain,path_basename(v->attestation))&&verify_live_candidate_anchors(v);}
static int run_live_preflight(const struct invocation *v){char *child[56],loader_fdpath[64],interpreter_fdpath[64],preload[MAX_PYTHON_PRELOAD],fdpath[64];char *env[]={env_path,env_lang,env_lc_all,env_tz,env_home,env_tmpdir,env_no_bytecode,env_no_plugins,(char*)0};usize fn=0;int n=0,status=0,bootstrap_fd=open_pinned_bootstrap();long pid;if(bootstrap_fd<0||!python_code_closure_matches()){if(bootstrap_fd>=0)syscall1(SYS_close,bootstrap_fd);return 126;}fdpath[0]='\0';if(!append_proc_fd(fdpath,sizeof(fdpath),&fn,bootstrap_fd)||!python_runtime_exec_prefix(child,56,&n,loader_fdpath,interpreter_fdpath,preload)){syscall1(SYS_close,bootstrap_fd);return 126;}child[n++]="-X";child[n++]=(char*)startup_pycache_option;child[n++]="-I";child[n++]="-B";child[n++]="-S";child[n++]=fdpath;child[n++]="preflight-fail-fast-enrich";child[n++]="--root";child[n++]=(char*)source_root;child[n++]="--";child[n++]="--output-root";child[n++]=(char*)v->output_root;child[n++]="--attestation";child[n++]=(char*)v->attestation;child[n++]="--native-preflight-envelope";child[n++]=(char*)v->preflight_path;child[n++]="--native-run-id";child[n++]=(char*)v->run_id;child[n++]="--native-nonce";child[n++]=(char*)v->nonce;child[n++]="--native-realtime-start-ns";child[n++]=(char*)v->realtime_start;child[n++]="--native-monotonic-start-ns";child[n++]=(char*)v->monotonic_start;child[n++]="--native-bootstrap-sha256";child[n++]=(char*)v->bootstrap_hash;child[n++]="--native-focused-receipt-sha256";child[n++]=(char*)v->focused_hash;child[n++]="--native-focused-sidecar-sha256";child[n++]=(char*)v->focused_sidecar_hash;child[n++]="--native-full-receipt-sha256";child[n++]=(char*)v->full_hash;child[n++]="--native-full-sidecar-sha256";child[n++]=(char*)v->full_sidecar_hash;child[n++]="--native-binary-contract-sha256";child[n++]=(char*)v->native_binary_contract_hash;child[n++]="--native-public-key-id";child[n++]=(char*)v->public_key_hash;child[n]=(char*)0;pid=syscall0(SYS_fork);if(pid<0){syscall1(SYS_close,bootstrap_fd);return 126;}if(pid==0){if(!python_code_closure_matches()||!inherit_python_runtime()||syscall3(SYS_fcntl,bootstrap_fd,F_SETFD,0)<0)syscall1(SYS_exit,126);syscall3(SYS_execve,(long)loader_fdpath,(long)child,(long)env);syscall1(SYS_exit,126);for(;;){}}syscall1(SYS_close,bootstrap_fd);if(syscall4(SYS_wait4,pid,(long)&status,0,0)<0)return 126;if(!pinned_bootstrap_path_valid()||!python_code_closure_matches())return 126;if((status&0x7f)==0)return(status>>8)&0xff;return 128+(status&0x7f);}
static int parse_live_preflight(struct invocation *v){u8 raw[MAX_CAPTURE];usize total=0,o=0;int ok=0;if(!read_regular_raw(v->preflight_path,0600,raw,&total))goto done;if(!consume_literal(raw,total,&o,"EGSI-LIVE-PREFLIGHT-V1\n")||!consume_exact_line(raw,total,&o,"run_id",v->run_id)||!consume_exact_line(raw,total,&o,"nonce",v->nonce)||!consume_exact_line(raw,total,&o,"realtime_start_ns",v->realtime_start)||!consume_exact_line(raw,total,&o,"monotonic_start_ns",v->monotonic_start)||!consume_hash_line(raw,total,&o,"pre_inventory_sha256",v->pre_inventory_hash)||!consume_expected_hash_line(raw,total,&o,"bootstrap_sha256",v->bootstrap_hash)||!consume_expected_hash_line(raw,total,&o,"focused_receipt_sha256",v->focused_hash)||!consume_expected_hash_line(raw,total,&o,"focused_sidecar_sha256",v->focused_sidecar_hash)||!consume_expected_hash_line(raw,total,&o,"full_receipt_sha256",v->full_hash)||!consume_expected_hash_line(raw,total,&o,"full_sidecar_sha256",v->full_sidecar_hash)||!consume_hash_line(raw,total,&o,"runner_lock_sha256",v->runner_lock_hash)||!consume_hash_line(raw,total,&o,"project_identity_sha256",v->project_identity_hash)||!consume_hash_line(raw,total,&o,"canonical_test_contract_sha256",v->canonical_contract_hash)||!consume_hash_line(raw,total,&o,"native_launcher_contract_sha256",v->native_launcher_contract_hash)||!consume_expected_hash_line(raw,total,&o,"native_binary_contract_sha256",v->native_binary_contract_hash)||!consume_expected_hash_line(raw,total,&o,"public_key_id",v->public_key_hash)||o!=total)goto done;ok=1;done:zero_bytes(raw,sizeof(raw));return ok;}
static int run_live_semantic_verifier(const struct invocation *v,int child_code){
    char *child[104],loader_fdpath[64],interpreter_fdpath[64],preload[MAX_PYTHON_PRELOAD],bootstrap_fdpath[64],attestation_fdpath[64],candidate_fdpath[64],snapshot_fdpath[64],child_code_text[4],attestation_fd_text[32],candidate_fd_text[32],snapshot_fd_text[32];
    char *env[]={env_path,env_lang,env_lc_all,env_tz,env_home,env_tmpdir,env_no_bytecode,env_no_plugins,(char*)0};
    usize bn=0,an=0,cn=0,sn=0,ccn=0,afn=0,cfn=0,sfn=0;int n=0,status=0,bootstrap_fd;long pid;
    if(v->candidate_artifact_fd<0||v->candidate_envelope_fd<0||v->semantic_snapshot_fd<0||!verify_live_candidate_anchors(v)||!python_code_closure_matches())return 126;
    bootstrap_fd=open_pinned_bootstrap();if(bootstrap_fd<0)return 126;
    bootstrap_fdpath[0]='\0';attestation_fdpath[0]='\0';candidate_fdpath[0]='\0';snapshot_fdpath[0]='\0';child_code_text[0]='\0';attestation_fd_text[0]='\0';candidate_fd_text[0]='\0';snapshot_fd_text[0]='\0';
    if(!append_decimal(child_code_text,sizeof(child_code_text),&ccn,(unsigned long)child_code)||!append_string(bootstrap_fdpath,sizeof(bootstrap_fdpath),&bn,"/proc/self/fd/")||!append_decimal(bootstrap_fdpath,sizeof(bootstrap_fdpath),&bn,(unsigned long)bootstrap_fd)||!append_string(attestation_fdpath,sizeof(attestation_fdpath),&an,"/proc/self/fd/")||!append_decimal(attestation_fdpath,sizeof(attestation_fdpath),&an,(unsigned long)v->candidate_artifact_fd)||!append_string(candidate_fdpath,sizeof(candidate_fdpath),&cn,"/proc/self/fd/")||!append_decimal(candidate_fdpath,sizeof(candidate_fdpath),&cn,(unsigned long)v->candidate_envelope_fd)||!append_string(snapshot_fdpath,sizeof(snapshot_fdpath),&sn,"/proc/self/fd/")||!append_decimal(snapshot_fdpath,sizeof(snapshot_fdpath),&sn,(unsigned long)v->semantic_snapshot_fd)||!append_decimal(attestation_fd_text,sizeof(attestation_fd_text),&afn,(unsigned long)v->candidate_artifact_fd)||!append_decimal(candidate_fd_text,sizeof(candidate_fd_text),&cfn,(unsigned long)v->candidate_envelope_fd)||!append_decimal(snapshot_fd_text,sizeof(snapshot_fd_text),&sfn,(unsigned long)v->semantic_snapshot_fd)){syscall1(SYS_close,bootstrap_fd);return 126;}
    if(!python_runtime_exec_prefix(child,104,&n,loader_fdpath,interpreter_fdpath,preload)){syscall1(SYS_close,bootstrap_fd);return 126;}child[n++]="-X";child[n++]=(char*)startup_pycache_option;child[n++]="-I";child[n++]="-B";child[n++]="-S";child[n++]=bootstrap_fdpath;child[n++]="verify-fail-fast-enrich";child[n++]="--root";child[n++]=(char*)source_root;child[n++]="--";
    child[n++]="--output-root";child[n++]=(char*)v->output_root;child[n++]="--case-file";child[n++]=(char*)v->case_file;child[n++]="--scope-case-file";child[n++]=(char*)v->scope_file;child[n++]="--attestation";child[n++]=attestation_fdpath;child[n++]="--mode";child[n++]="verify-only";child[n++]="--native-candidate-envelope";child[n++]=candidate_fdpath;
    child[n++]="--native-attestation-path";child[n++]=(char*)v->attestation;child[n++]="--native-attestation-fd";child[n++]=attestation_fd_text;child[n++]="--native-candidate-envelope-path";child[n++]=(char*)v->candidate_path;child[n++]="--native-candidate-envelope-fd";child[n++]=candidate_fd_text;
    child[n++]="--native-semantic-snapshot";child[n++]=snapshot_fdpath;child[n++]="--native-semantic-snapshot-path";child[n++]=(char*)v->snapshot_path;child[n++]="--native-semantic-snapshot-fd";child[n++]=snapshot_fd_text;
    child[n++]="--native-run-id";child[n++]=(char*)v->run_id;child[n++]="--native-nonce";child[n++]=(char*)v->nonce;child[n++]="--native-realtime-start-ns";child[n++]=(char*)v->realtime_start;child[n++]="--native-monotonic-start-ns";child[n++]=(char*)v->monotonic_start;child[n++]="--native-child-exit-code";child[n++]=child_code_text;child[n++]="--native-pre-inventory-sha256";child[n++]=(char*)v->pre_inventory_hash;child[n++]="--native-bootstrap-sha256";child[n++]=(char*)v->bootstrap_hash;child[n++]="--native-focused-receipt-sha256";child[n++]=(char*)v->focused_hash;child[n++]="--native-focused-sidecar-sha256";child[n++]=(char*)v->focused_sidecar_hash;child[n++]="--native-full-receipt-sha256";child[n++]=(char*)v->full_hash;child[n++]="--native-full-sidecar-sha256";child[n++]=(char*)v->full_sidecar_hash;child[n++]="--native-runner-lock-sha256";child[n++]=(char*)v->runner_lock_hash;child[n++]="--native-project-identity-sha256";child[n++]=(char*)v->project_identity_hash;child[n++]="--native-canonical-test-contract-sha256";child[n++]=(char*)v->canonical_contract_hash;child[n++]="--native-launcher-contract-sha256";child[n++]=(char*)v->native_launcher_contract_hash;child[n++]="--native-binary-contract-sha256";child[n++]=(char*)v->native_binary_contract_hash;child[n++]="--native-public-key-id";child[n++]=(char*)v->public_key_hash;child[n]=(char*)0;
    pid=syscall0(SYS_fork);if(pid<0){syscall1(SYS_close,bootstrap_fd);return 126;}if(pid==0){if(!python_code_closure_matches()||!inherit_python_runtime()||syscall3(SYS_fcntl,bootstrap_fd,F_SETFD,0)<0||syscall3(SYS_fcntl,v->candidate_artifact_fd,F_SETFD,0)<0||syscall3(SYS_fcntl,v->candidate_envelope_fd,F_SETFD,0)<0||syscall3(SYS_fcntl,v->semantic_snapshot_fd,F_SETFD,0)<0)syscall1(SYS_exit,126);syscall3(SYS_execve,(long)loader_fdpath,(long)child,(long)env);write_text(2,"locked live semantic verifier execve failed\n");syscall1(SYS_exit,126);for(;;){}}
    syscall1(SYS_close,bootstrap_fd);if(syscall4(SYS_wait4,pid,(long)&status,0,0)<0)return 126;if(!pinned_bootstrap_path_valid()||!verify_live_candidate_anchors(v)||!python_code_closure_matches())return 126;if((status&0x7f)==0)return(status>>8)&0xff;return 128+(status&0x7f);
}
static int parse_live_candidate(struct invocation *v,int child_code,int capture){
    u8 raw[MAX_CAPTURE],artifact_digest[32],candidate_digest[32];char artifact_hash[72],observed_post[72],observed_artifact[72],observed_commitment[72],child_text[4];usize total=0,o=0,cn=0;int ok=0;
    if(capture){if(!read_regular_raw(v->candidate_path,0600,raw,&total)||!hash_file(v->candidate_path,0600,MAX_CAPTURE,candidate_digest)||!hash_file(v->attestation,0600,MAX_ARTIFACT_BYTES,artifact_digest))goto done;}
    else{if(!read_held_anchor_raw(v->candidate_envelope_fd,0600,&v->candidate_envelope_anchor,raw,&total)||!held_file_anchor_matches(v->candidate_artifact_fd,0600,MAX_ARTIFACT_BYTES,&v->candidate_artifact_anchor))goto done;copy_bytes(candidate_digest,v->candidate_envelope_anchor.digest,32);copy_bytes(artifact_digest,v->candidate_artifact_anchor.digest,32);}
    digest_text(artifact_digest,artifact_hash);child_text[0]='\0';if(!append_decimal(child_text,sizeof(child_text),&cn,(unsigned long)child_code))goto done;
    if(!consume_literal(raw,total,&o,"EGSI-LIVE-CANDIDATE-V1\n")||!consume_exact_line(raw,total,&o,"run_id",v->run_id)||!consume_exact_line(raw,total,&o,"nonce",v->nonce)||!consume_exact_line(raw,total,&o,"realtime_start_ns",v->realtime_start)||!consume_exact_line(raw,total,&o,"monotonic_start_ns",v->monotonic_start)||!consume_expected_hash_line(raw,total,&o,"pre_inventory_sha256",v->pre_inventory_hash)||!consume_expected_hash_line(raw,total,&o,"bootstrap_sha256",v->bootstrap_hash)||!consume_expected_hash_line(raw,total,&o,"focused_receipt_sha256",v->focused_hash)||!consume_expected_hash_line(raw,total,&o,"focused_sidecar_sha256",v->focused_sidecar_hash)||!consume_expected_hash_line(raw,total,&o,"full_receipt_sha256",v->full_hash)||!consume_expected_hash_line(raw,total,&o,"full_sidecar_sha256",v->full_sidecar_hash)||!consume_expected_hash_line(raw,total,&o,"runner_lock_sha256",v->runner_lock_hash)||!consume_expected_hash_line(raw,total,&o,"project_identity_sha256",v->project_identity_hash)||!consume_expected_hash_line(raw,total,&o,"canonical_test_contract_sha256",v->canonical_contract_hash)||!consume_expected_hash_line(raw,total,&o,"native_launcher_contract_sha256",v->native_launcher_contract_hash)||!consume_expected_hash_line(raw,total,&o,"native_binary_contract_sha256",v->native_binary_contract_hash)||!consume_expected_hash_line(raw,total,&o,"public_key_id",v->public_key_hash)||!(capture?consume_hash_line(raw,total,&o,"semantic_snapshot_sha256",v->semantic_snapshot_hash):consume_expected_hash_line(raw,total,&o,"semantic_snapshot_sha256",v->semantic_snapshot_hash))||!consume_exact_line(raw,total,&o,"child_exit_code",child_text)||!consume_exact_line(raw,total,&o,"terminal_status",child_code==0?"PASS":"STOP")||!consume_hash_line(raw,total,&o,"post_inventory_sha256",observed_post)||!consume_hash_line(raw,total,&o,"attestation_sha256",observed_artifact)||!consume_hash_line(raw,total,&o,"attestation_commitment_sha256",observed_commitment)||o!=total||!string_equal(observed_artifact,artifact_hash))goto done;
    if(capture){copy_bytes((u8*)v->post_inventory_hash,(const u8*)observed_post,72);copy_bytes((u8*)v->candidate_attestation_hash,(const u8*)observed_artifact,72);copy_bytes((u8*)v->candidate_commitment_hash,(const u8*)observed_commitment,72);copy_bytes(v->candidate_file_hash,candidate_digest,32);copy_bytes(v->candidate_artifact_file_hash,artifact_digest,32);}
    else if(!string_equal(v->post_inventory_hash,observed_post)||!string_equal(v->candidate_attestation_hash,observed_artifact)||!string_equal(v->candidate_commitment_hash,observed_commitment)||!constant_equal(v->candidate_file_hash,candidate_digest,32)||!constant_equal(v->candidate_artifact_file_hash,artifact_digest,32)||!verify_live_candidate_anchors(v))goto done;
    ok=1;
 done:zero_bytes(raw,sizeof(raw));zero_bytes(artifact_digest,sizeof(artifact_digest));zero_bytes(candidate_digest,sizeof(candidate_digest));return ok;
}
#endif

static int format_preimage_from_digest(const char *domain,const char *name,const u8 artifact_digest[32],char out[MAX_CAPTURE],usize *outn){char ahex[65],khex[65],chex[65];usize n=0;to_hex(artifact_digest,32,ahex);to_hex(native_key_id,32,khex);to_hex(native_contract_value,32,chex);out[0]='\0';if(!append_string(out,MAX_CAPTURE,&n,"EGSI-NATIVE-ATTESTATION-V2\nalgorithm=")||!append_string(out,MAX_CAPTURE,&n,algorithm)||!append_string(out,MAX_CAPTURE,&n,"\ndomain=")||!append_string(out,MAX_CAPTURE,&n,domain)||!append_string(out,MAX_CAPTURE,&n,"\nartifact=")||!append_string(out,MAX_CAPTURE,&n,name)||!append_string(out,MAX_CAPTURE,&n,"\nartifact_sha256=")||!append_string(out,MAX_CAPTURE,&n,ahex)||!append_string(out,MAX_CAPTURE,&n,"\nnative_contract=")||!append_string(out,MAX_CAPTURE,&n,chex)||!append_string(out,MAX_CAPTURE,&n,"\nkey_id=")||!append_string(out,MAX_CAPTURE,&n,khex)||!append_string(out,MAX_CAPTURE,&n,"\n"))return 0;*outn=n;return 1;}
static int build_preimage(const char *artifact,const char *domain,const char *name,char out[MAX_CAPTURE],usize *outn){u8 digest[32];int ok;if(!hash_file(artifact,0600,MAX_ARTIFACT_BYTES,digest))return 0;ok=format_preimage_from_digest(domain,name,digest,out,outn);zero_bytes(digest,sizeof(digest));return ok;}
static int read_sidecar_raw(const char *path,u8 out[MAX_CAPTURE],usize expected_n){long fd=syscall3(SYS_open,(long)path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0),count;struct kernel_stat before,after;usize o=0;int ok=0;if(fd<0||expected_n>MAX_CAPTURE)return 0;if(syscall2(SYS_fstat,fd,(long)&before)<0||!stat_expected(&before,0600,MAX_CAPTURE)||(usize)before.size!=expected_n||!fd_path_is_exact((int)fd,path))goto done;while(o<expected_n){count=syscall3(SYS_read,fd,(long)(out+o),(long)(expected_n-o));if(count<=0)goto done;o+=(usize)count;}count=syscall3(SYS_read,fd,(long)out,1);if(count!=0||syscall2(SYS_fstat,fd,(long)&after)<0||!stat_same(&before,&after))goto done;ok=1;done:if(fd>=0)syscall1(SYS_close,fd);return ok;}
static int remove_sidecar(const char *artifact){char p[MAX_PATH];long r;if(!concat2(p,artifact,sidecar_suffix))return 0;r=syscall1(SYS_unlink,(long)p);return r==0||r==-2;}
#if LAUNCH_KIND == 4
static int cleanup_live_all_paths(const struct invocation *v){int ok=1;if(!remove_sidecar(v->attestation))ok=0;if(!remove_path(v->attestation))ok=0;if(!remove_path(v->preflight_path))ok=0;if(!remove_path(v->candidate_path))ok=0;if(!remove_path(v->snapshot_path))ok=0;return ok;}
static int cleanup_live_transient_paths(const struct invocation *v){int ok=1;if(!remove_path(v->preflight_path))ok=0;if(!remove_path(v->candidate_path))ok=0;return ok;}
#endif
#if LAUNCH_KIND == 1 || LAUNCH_KIND == 2 || LAUNCH_KIND == 4
static int publish_attestation(const char *artifact,const char *domain,const char *name,const u8 *expected_digest){char sidecar[MAX_PATH],parent[MAX_PATH],tmp[MAX_PATH],raw[MAX_CAPTURE],shex[513];const char *side_name;u8 observed_digest[32],signature[RSA_BYTES];usize raw_n=0,tmp_n=0,written=0;long pfd=-1,fd=-1,count,result;unsigned long pid=(unsigned long)syscall0(SYS_getpid);int ok=0;if(!concat2(sidecar,artifact,sidecar_suffix)||!parent_path(sidecar,parent))return 0;if(expected_digest){if(!hash_file(artifact,0600,MAX_ARTIFACT_BYTES,observed_digest)||!constant_equal(observed_digest,expected_digest,32)||!format_preimage_from_digest(domain,name,expected_digest,raw,&raw_n))goto done;}else if(!build_preimage(artifact,domain,name,raw,&raw_n))goto done;if(!rsa_sign((const u8*)raw,raw_n,signature))goto done;to_hex(signature,RSA_BYTES,shex);if(!append_string(raw,MAX_CAPTURE,&raw_n,"signature=")||!append_string(raw,MAX_CAPTURE,&raw_n,shex)||!append_string(raw,MAX_CAPTURE,&raw_n,"\n"))goto done;pfd=syscall3(SYS_open,(long)parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,0);if(pfd<0||!fd_path_is_exact((int)pfd,parent))goto done;side_name=path_basename(sidecar);tmp[0]='\0';if(!append_string(tmp,MAX_PATH,&tmp_n,".")||!append_string(tmp,MAX_PATH,&tmp_n,side_name)||!append_string(tmp,MAX_PATH,&tmp_n,".")||!append_decimal(tmp,MAX_PATH,&tmp_n,pid)||!append_string(tmp,MAX_PATH,&tmp_n,".tmp"))goto done;fd=syscall4(SYS_openat,pfd,(long)tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)goto done;while(written<raw_n){count=syscall3(SYS_write,fd,(long)(raw+written),(long)(raw_n-written));if(count<=0)goto done;written+=(usize)count;}if(syscall1(SYS_fsync,fd)<0||syscall1(SYS_close,fd)<0){fd=-1;goto done;}fd=-1;result=syscall5(SYS_renameat2,pfd,(long)tmp,pfd,(long)side_name,RENAME_NOREPLACE);if(result<0||syscall1(SYS_fsync,pfd)<0)goto done;ok=1;done:if(fd>=0)syscall1(SYS_close,fd);if(!ok&&pfd>=0&&tmp[0])syscall3(SYS_unlinkat,pfd,(long)tmp,0);if(pfd>=0)syscall1(SYS_close,pfd);zero_bytes(observed_digest,sizeof(observed_digest));zero_bytes((u8*)raw,sizeof(raw));zero_bytes(signature,sizeof(signature));zero_bytes((u8*)shex,sizeof(shex));return ok;}
#endif
static int verify_attestation(const char *artifact,const char *domain,const char *name){char sidecar[MAX_PATH],preimage[MAX_CAPTURE];u8 observed[MAX_CAPTURE],signature[RSA_BYTES];usize n=0,total;int ok=0;if(!concat2(sidecar,artifact,sidecar_suffix)||!build_preimage(artifact,domain,name,preimage,&n))return 0;total=n+10+512+1;if(total>MAX_CAPTURE||!read_sidecar_raw(sidecar,observed,total))goto done;if(!constant_equal((const u8*)preimage,observed,n)||!constant_equal(observed+n,(const u8*)"signature=",10)||observed[total-1]!='\n'||!from_hex_lower((const char*)(observed+n+10),512,signature))goto done;ok=rsa_verify((const u8*)preimage,n,signature);done:zero_bytes((u8*)preimage,sizeof(preimage));zero_bytes(observed,sizeof(observed));zero_bytes(signature,sizeof(signature));return ok;}
#if LAUNCH_KIND == 5
static int verify_held_live_artifact_anchors(const struct invocation *v){char preimage[MAX_CAPTURE];u8 observed[MAX_CAPTURE],signature[RSA_BYTES];usize n=0,total=0,observed_n=0;int ok=0;if(!held_file_anchor_matches(v->live_artifact_fd,0600,MAX_ARTIFACT_BYTES,&v->live_artifact_anchor)||!format_preimage_from_digest(live_domain,path_basename(v->attestation),v->live_artifact_anchor.digest,preimage,&n))goto done;total=n+10+512+1;if(total>MAX_CAPTURE||!read_held_anchor_raw(v->live_sidecar_fd,0600,&v->live_sidecar_anchor,observed,&observed_n)||observed_n!=total||!constant_equal((const u8*)preimage,observed,n)||!constant_equal(observed+n,(const u8*)"signature=",10)||observed[total-1]!='\n'||!from_hex_lower((const char*)(observed+n+10),512,signature)||!rsa_verify((const u8*)preimage,n,signature)||!held_file_anchor_matches(v->live_artifact_fd,0600,MAX_ARTIFACT_BYTES,&v->live_artifact_anchor))goto done;ok=1;done:zero_bytes((u8*)preimage,sizeof(preimage));zero_bytes(observed,sizeof(observed));zero_bytes(signature,sizeof(signature));return ok;}
#endif
static int verify_all(const struct invocation *v){return verify_attestation(v->focused,focused_domain,focused_basename)&&verify_attestation(v->full,full_domain,full_basename)&&verify_attestation(v->report,report_domain,report_basename);}

__attribute__((noinline,used)) static int launcher_main(usize *stack){int argc=(int)stack[0],child_code;char **argv=(char**)&stack[1];struct invocation v;
#if LAUNCH_KIND == 1 || LAUNCH_KIND == 2 || LAUNCH_KIND == 4
    if(!harden_signer()){diagnostic("native signer hardening failed\n");return 70;}
#endif
    zero_bytes((u8*)&v,sizeof(v));v.live_artifact_fd=-1;v.live_sidecar_fd=-1;v.live_parent_fd=-1;v.candidate_artifact_fd=-1;v.candidate_envelope_fd=-1;v.semantic_snapshot_fd=-1;
#if LAUNCH_KIND == 4 || LAUNCH_KIND == 5
    initialize_live_directory_chains(&v);
#endif
    if(!self_path_is_exact()){diagnostic("locked launcher installed path mismatch\n");return 65;}if(argc<1||argc>MAX_USER_ARGS||
#if LAUNCH_KIND == 1
    !receipt_arguments(argc,argv,&v)
#elif LAUNCH_KIND == 2 || LAUNCH_KIND == 3
    !gate_arguments(argc,argv,&v)
#else
    !live_arguments(argc,argv,&v)
#endif
    ){diagnostic("invalid locked launcher invocation\n");return 64;}if(v.public_mode){if(!open_python_runtime()){diagnostic("native Python runtime closure failed\n");return 66;}if(!open_python_startup_code()){diagnostic("native Python startup code closure failed\n");return 66;}if(!public_contract()){diagnostic("native public contract failed\n");return 66;}return 0;}
#if LAUNCH_KIND == 1 || LAUNCH_KIND == 2 || LAUNCH_KIND == 4
    if(v.security_mode){if(!signer_security_state()){diagnostic("native signer security state failed\n");return 70;}return 0;}
#endif
    if(v.help){if(!open_python_runtime()){diagnostic("native Python runtime closure failed\n");return 66;}if(!open_python_startup_code()){diagnostic("native Python startup code closure failed\n");return 66;}return run_child(argc,argv,&v);}
#if LAUNCH_KIND == 4
    if(!prepare_live_invocation(&v)||!prepare_live_paths(&v)){diagnostic("native live invocation generation failed\n");return 66;}
    if(!ensure_directory_exists(v.attestation_parent)||!cleanup_live_all_paths(&v)){diagnostic("native live candidate cleanup failed\n");return 66;}
#endif
    if(!open_python_runtime()){diagnostic("native Python runtime closure failed\n");return 66;}if(!open_python_startup_code()){diagnostic("native Python startup code closure failed\n");return 66;}
#if LAUNCH_KIND == 1
    if(!remove_sidecar(v.output)){diagnostic("native sidecar cleanup failed\n");return 66;}child_code=run_child(argc,argv,&v);if(child_code!=0){remove_sidecar(v.output);remove_path(v.output);return child_code;}if(!python_code_closure_matches()||!publish_attestation(v.output,string_equal(v.name,"focused")?focused_domain:full_domain,path_basename(v.output),(const u8*)0)||!python_code_closure_matches()){remove_sidecar(v.output);diagnostic("native receipt attestation failed\n");return 66;}write_text(1,"EGSI_NATIVE_ATTESTED=receipt\n");return 0;
#elif LAUNCH_KIND == 2
    if(!remove_sidecar(v.report)){diagnostic("native sidecar cleanup failed\n");return 66;}child_code=run_child(argc,argv,&v);if(child_code!=0){remove_sidecar(v.report);remove_path(v.report);return child_code;}if(!verify_attestation(v.focused,focused_domain,focused_basename)||!verify_attestation(v.full,full_domain,full_basename)||!python_code_closure_matches()||!publish_attestation(v.report,report_domain,report_basename,(const u8*)0)||!python_code_closure_matches()){remove_sidecar(v.report);diagnostic("native report attestation failed\n");return 66;}write_text(1,"EGSI_NATIVE_ATTESTED=report\n");return 0;
#elif LAUNCH_KIND == 3
    if(!verify_all(&v)){diagnostic("native pre-python attestation verification failed\n");return 66;}child_code=run_child(argc,argv,&v);if(child_code!=0)return child_code;if(!verify_all(&v)){diagnostic("native post-python attestation verification failed\n");return 66;}return 0;
#elif LAUNCH_KIND == 4
    if(!capture_live_base_directory_chains(&v)||!capture_live_receipt_anchors(&v)){close_live_directory_chains(&v);diagnostic("native live receipt preflight failed\n");return 66;}
    if(run_live_preflight(&v)!=0||!parse_live_preflight(&v)||!verify_live_receipt_anchors(&v)){close_live_directory_chains(&v);cleanup_live_all_paths(&v);diagnostic("native live trust preflight failed\n");return 66;}
    child_code=run_child(argc,argv,&v);
    if(child_code!=0&&child_code!=120){close_live_directory_chains(&v);cleanup_live_all_paths(&v);return child_code;}
    if(!live_base_directory_chains_match(&v)||!parse_live_candidate(&v,child_code,1)||!capture_live_candidate_anchors(&v)){close_live_candidate_fds(&v);close_live_directory_chains(&v);cleanup_live_all_paths(&v);diagnostic("native live candidate binding failed\n");return 66;}
    if(run_live_semantic_verifier(&v,child_code)!=0||!parse_live_candidate(&v,child_code,0)||!verify_live_receipt_anchors(&v)||!verify_live_candidate_anchors(&v)){close_live_candidate_fds(&v);close_live_directory_chains(&v);cleanup_live_all_paths(&v);diagnostic("native live semantic verification failed\n");return 66;}
    if(!live_base_directory_chains_match(&v)||!verify_live_candidate_anchors(&v)||!python_code_closure_matches()){close_live_candidate_fds(&v);close_live_directory_chains(&v);cleanup_live_all_paths(&v);diagnostic("native live path-chain verification failed\n");return 66;}
    if(!python_code_closure_matches()||!publish_attestation(v.attestation,live_domain,path_basename(v.attestation),v.candidate_artifact_file_hash)||!python_code_closure_matches()||!refresh_directory_chain_leaf_after_owned_mutation(&v.live_chain)||!verify_published_live_candidate(&v)){close_live_candidate_fds(&v);close_live_directory_chains(&v);cleanup_live_all_paths(&v);diagnostic("native live attestation failed\n");return 66;}
    close_live_candidate_fds(&v);
    close_live_directory_chains(&v);
    if(!cleanup_live_transient_paths(&v)){cleanup_live_all_paths(&v);diagnostic("native live transient cleanup failed\n");return 66;}
    if(!python_code_closure_matches()){cleanup_live_all_paths(&v);diagnostic("native Python code closure changed before return\n");return 66;}if(child_code==120){write_text(1,"EGSI_NATIVE_ATTESTED=live-enrichment-stop\n");return 120;}write_text(1,"EGSI_NATIVE_ATTESTED=live-enrichment\n");return 0;
#else
    if(!prepare_live_paths(&v)||!capture_live_base_directory_chains(&v)||!capture_live_receipt_anchors(&v)||!capture_live_artifact_anchors(&v)){close_live_artifact_fds(&v);close_live_directory_chains(&v);diagnostic("native live pre-python attestation verification failed\n");return 66;}
    child_code=run_child(argc,argv,&v);
    if(child_code!=0){close_live_artifact_fds(&v);close_live_directory_chains(&v);return child_code;}
    if(!verify_live_receipt_anchors(&v)||!verify_live_artifact_anchors(&v)){close_live_artifact_fds(&v);close_live_directory_chains(&v);diagnostic("native live post-python attestation verification failed\n");return 66;}
    if(!python_code_closure_matches()){close_live_artifact_fds(&v);close_live_directory_chains(&v);diagnostic("native Python code closure changed before return\n");return 66;}close_live_artifact_fds(&v);close_live_directory_chains(&v);return 0;
#endif
}

__attribute__((naked,noreturn,used)) void _start(void){__asm__ volatile("mov %rsp, %rdi\n""andq $-16, %rsp\n""call launcher_main\n""mov %eax, %edi\n""mov $60, %eax\n""syscall\n""ud2\n");}
