package com.swm.sdk;

@FunctionalInterface
public interface ProgressListener {
    void onProgress(long written, long total);
}
