from setuptools import setup

setup(name='kpwndfu',
      version='1.0.0',
      description='python3 module implementation of axi0mx\'s checkm8 exploit',
      author='kritanta',
      url='https://github.com/kritantadev/checkm8',
      install_requires=['pyusb @ git+git://github.com/kritantadev/pyusb.git'],
      packages=['checkm8', 'libusbfinder', 'kpwndfu'],
      package_dir={
          'checkm8': 'src/checkm8',
          'libusbfinder': 'src/libusbfinder',
          'kpwndfu': 'src/kpwndfu'
      },
      package_data={
          'checkm8': ['devices/*', 'bin/*'],
          'libusbfinder': ['bottles/*'],
          'kpwndfu': ['devices/*']
      },
      scripts=['bin/kpwndfu']
      )