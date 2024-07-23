## Description

Frida script template project for android written in TypeScript.
集成了常见的反反调试，详细的Native 层跟踪打印（包括可变参数函数的参数打印，并且会根据参数类型进行解析打印）

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
