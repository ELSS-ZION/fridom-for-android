import frida, sys, io

apkPackageName = 'com.ximalaya.ting.android'
# sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='utf8')
sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='gb18030')

def on_message(message, data):
    if message['type'] == 'send':
        print("{0}".format(message['payload']), flush=True)
    else:
        print(message, flush=True)

with open('_src.js', 'r') as jsFile:
  jscode = jsFile.read()

if __name__ == '__main__':

  hook_mode = '-silent'

  if len(sys.argv) >= 2:
    hook_mode = sys.argv[1]

  if hook_mode == '-launch':
    pid = frida.get_usb_device().spawn([apkPackageName])
    session = frida.get_usb_device().attach(pid)
  else:
    session = frida.get_usb_device().attach(apkPackageName)
    
  script  = session.create_script(jscode)
  script.on('message', on_message)
  script.load()

  try:
    while True:
      pass

  except KeyboardInterrupt:
      session.detach()
      sys.exit(0)

