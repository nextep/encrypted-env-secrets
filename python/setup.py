from setuptools import setup, find_packages

setup(
    name='envshield',
    version='1.0.0',
    description='A universal, zero-dependency Just-In-Time (JIT) environment variable encryption system.',
    author='EnvShield Team',
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.6',
)
