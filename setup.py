from setuptools import setup

setup(name='checkm8',
      version='1.0.0',
      description='python3 module implementation of axi0mx\'s checkm8 exploit',
      author='kritanta',
      url='https://github.com/kritantadev/checkm8',
      install_requires=['pyusb'],
      packages=['checkm8', 'libusbfinder'],
      package_dir={
          'checkm8': 'src/checkm8',
          'libusbfinder': 'src/libusbfinder',
      },
      package_data={
          'checkm8': ['devices/*', 'bin/*'],
      },
      scripts=['bin/checkm8']
      )