from distutils.core import setup
import glob

NAME='leftokill'

def get_ver():
    try:
        with open(NAME+'.spec') as f:
            for line in f:
                if "Version:" in line:
                    return line.split()[1]
    except IOError:
        print "Make sure that %s is in directory"  % (NAME+'.spec')
        raise SystemExit(1)

setup(
    name = NAME,
    version = get_ver(),
    author = 'SRCE',
    author_email = 'dvrcic@srce.hr',
    license = 'GPL',
    description = 'Unix daemon that cleans the processes/threads left by the job scheduler',
    long_description = 'Unix daemon that cleans the processes/threads left by the job scheduler',
    url = 'https://github.com/vrdel/leftokill',
    package_dir = {'leftokill': 'pymodule/'},
    packages = ['leftokill'],
    data_files = [('/etc/leftokill', glob.glob('config/*.conf')),
                  ('/etc/init.d/', glob.glob('init/leftokill'))],
    scripts = glob.glob('exec/*') + glob.glob('simul/*')
    )
