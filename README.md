## Description

Frida script template project for android written in TypeScript.

## Usage

---

### Startup

+ install dependencies

```sh
$ npm install
```

+ write package name in `hook.py` file

```
apkPackageName = '{{xxx.xxx.xxx}}'
```

+ write frida hook scripts

```
src/index.ts
```

### Spawn a new process and hook

```sh
$ npm run launch-hook
```

### Hook after start the process

```sh
$ npm run silent-hook
```

---

## Features

+ antidebug-bypass

+ jni-trace

+ TypeScript

+ npm module management