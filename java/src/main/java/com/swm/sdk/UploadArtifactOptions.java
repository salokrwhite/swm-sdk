package com.swm.sdk;

public final class UploadArtifactOptions {
    private String platform;
    private String arch;
    private String fileType;
    private String filePath;
    private String signature;
    private boolean replace;

    public String getPlatform() {
        return platform;
    }

    public UploadArtifactOptions setPlatform(String platform) {
        this.platform = platform;
        return this;
    }

    public String getArch() {
        return arch;
    }

    public UploadArtifactOptions setArch(String arch) {
        this.arch = arch;
        return this;
    }

    public String getFileType() {
        return fileType;
    }

    public UploadArtifactOptions setFileType(String fileType) {
        this.fileType = fileType;
        return this;
    }

    public String getFilePath() {
        return filePath;
    }

    public UploadArtifactOptions setFilePath(String filePath) {
        this.filePath = filePath;
        return this;
    }

    public String getSignature() {
        return signature;
    }

    public UploadArtifactOptions setSignature(String signature) {
        this.signature = signature;
        return this;
    }

    public boolean isReplace() {
        return replace;
    }

    public UploadArtifactOptions setReplace(boolean replace) {
        this.replace = replace;
        return this;
    }
}
