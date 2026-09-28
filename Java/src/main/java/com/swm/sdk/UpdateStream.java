package com.swm.sdk;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Handle for an update or Debug server-sent-event stream.
 */
public final class UpdateStream implements AutoCloseable {
    @FunctionalInterface
    public interface EventListener {
        void onEvent(SwmModels.UpdateEvent event);
    }

    @FunctionalInterface
    public interface ErrorListener {
        void onError(SwmException error);
    }

    @FunctionalInterface
    public interface ControlListener {
        void onControl(SwmModels.UpdateEvent event);
    }

    private final AtomicBoolean running = new AtomicBoolean(true);
    private final Thread worker;
    private volatile AutoCloseable closeable;

    UpdateStream(Consumer<UpdateStream> workerBody) {
        this.worker = new Thread(() -> {
            try {
                workerBody.accept(this);
            } finally {
                running.set(false);
            }
        }, "swm-update-stream");
        this.worker.setDaemon(true);
        this.worker.start();
    }

    public boolean running() {
        return running.get();
    }

    public void stop() {
        if (running.getAndSet(false)) {
            var current = closeable;
            if (current != null) {
                try {
                    current.close();
                } catch (Exception ignored) {
                    // Closing the transport is best effort.
                }
            }
            worker.interrupt();
        }
    }

    void attach(AutoCloseable value) {
        closeable = value;
        if (!running.get() && value != null) {
            try {
                value.close();
            } catch (Exception ignored) {
                // Closing the transport is best effort.
            }
        }
    }

    @Override
    public void close() {
        stop();
    }
}
