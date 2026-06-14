package com.swm.sdk;

public final class UpdateWatchHandle implements AutoCloseable {
    private final Thread worker;

    UpdateWatchHandle(Thread worker) {
        this.worker = worker;
    }

    public void stop() {
        worker.interrupt();
    }

    @Override
    public void close() {
        stop();
    }
}
