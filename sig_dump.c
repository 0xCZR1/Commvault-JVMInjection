#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <jni.h>
#include <jvmti.h>

static void dump_methods(jvmtiEnv* ti, FILE* f, jclass c, const char* sig){
    fprintf(f, "== %s ==\n", sig);
    jint mc; jmethodID* m;
    if ((*ti)->GetClassMethods(ti,c,&mc,&m)==JVMTI_ERROR_NONE){
        for (jint i=0;i<mc;i++){
            char *nm=0,*s=0; jint mod=0;
            (*ti)->GetMethodName(ti,m[i],&nm,&s,NULL);
            (*ti)->GetMethodModifiers(ti,m[i],&mod);
            fprintf(f,"  %s%s %s\n",(mod&8)?"static ":"",nm?nm:"?",s?s:"?");
            (*ti)->Deallocate(ti,(unsigned char*)nm);
            (*ti)->Deallocate(ti,(unsigned char*)s);
        }
        (*ti)->Deallocate(ti,(unsigned char*)m);
    }
}

DWORD WINAPI go(LPVOID _) {
    FILE* f = fopen("C:\\Users\\Public\\o.txt", "w");
    if (!f) return 1;
    typedef jint (JNICALL *GetVMs)(JavaVM**, jsize, jsize*);
    GetVMs gv = (GetVMs)GetProcAddress(GetModuleHandleA("jvm.dll"), "JNI_GetCreatedJavaVMs");
    if (!gv) { fprintf(f,"no export\n"); fclose(f); return 2; }
    JavaVM* vm; jsize n;
    if (gv(&vm,1,&n) || !n) { fprintf(f,"no vm\n"); fclose(f); return 3; }
    JNIEnv* env;
    if ((*vm)->AttachCurrentThread(vm,(void**)&env,NULL)) { fprintf(f,"attach fail\n"); fclose(f); return 4; }
    jvmtiEnv* ti = NULL;
    if ((*vm)->GetEnv(vm,(void**)&ti,JVMTI_VERSION_1_2) || !ti) { fprintf(f,"no jvmti\n"); fclose(f); return 5; }
    fprintf(f,"attached + jvmti ok\n");
    jint cc; jclass* classes;
    if ((*ti)->GetLoadedClasses(ti,&cc,&classes) != JVMTI_ERROR_NONE) { fprintf(f,"fail\n"); fclose(f); return 6; }

    for (jint i=0;i<cc;i++){
        char* sig=NULL;
        if ((*ti)->GetClassSignature(ti,classes[i],&sig,NULL)==JVMTI_ERROR_NONE && sig){
            if (strcmp(sig,"Lcommvault/cte/util/PasswordEncoder;")==0 ||
                strcmp(sig,"Lcommvault/qnet/sys/CVPassword;")==0 ||
                strcmp(sig,"Lcommvault/cte/common/xml/Password;")==0 ||
                strcmp(sig,"Lcommvault/msgs/Common/UserPassword;")==0)
                dump_methods(ti, f, classes[i], sig);
            (*ti)->Deallocate(ti,(unsigned char*)sig);
        }
    }

    (*ti)->Deallocate(ti,(unsigned char*)classes);
    fclose(f);
    (*vm)->DetachCurrentThread(vm);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l){
    if (r==DLL_PROCESS_ATTACH){ DisableThreadLibraryCalls(h); CreateThread(0,0,go,0,0,0); }
    return TRUE;
}
