FROM python:3.11-slim-bookworm

# Install deps
RUN apt-get update && apt-get install -y \
    openjdk-17-jre-headless \
    wget unzip curl git \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# apktool
RUN wget https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar -O /usr/local/bin/apktool.jar \
    && echo '#!/bin/sh\nexec java -jar /usr/local/bin/apktool.jar "$@"' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# Android SDK + cmdline tools
RUN mkdir -p /android-sdk/cmdline-tools && cd /android-sdk/cmdline-tools \
    && wget -q https://dl.google.com/android/repository/commandlinetools-linux-10406996_latest.zip -O cmdtools.zip \
    && unzip cmdtools.zip -d . && rm cmdtools.zip \
    && mkdir -p /android-sdk/cmdline-tools/latest \
    && mv /android-sdk/cmdline-tools/cmdline-tools/* /android-sdk/cmdline-tools/latest/

ENV ANDROID_HOME=/android-sdk
ENV PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/build-tools/35.0.0

# Install build-tools + platform-tools (adb lives here)
RUN yes | sdkmanager --sdk_root=${ANDROID_HOME} --licenses \
    && sdkmanager --sdk_root=${ANDROID_HOME} "build-tools;35.0.0" "platform-tools"

# Copy code
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# Set env paths
ENV APKTOOL_JAR=/usr/local/bin/apktool.jar
ENV AAPT_PATH=/android-sdk/build-tools/35.0.0/aapt
ENV ADB_PATH=/android-sdk/platform-tools/adb

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
