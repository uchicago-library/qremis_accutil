from setuptools import setup, find_packages


def readme():
    with open("README.md", 'r') as f:
        return f.read()


setup(
    name="accutil",
    description="The qremis accutil is a utility for performing " +
    "accessions in the qremis based microservice environment for a digital repository.",
    version="0.0.3",
    long_description=readme(),
    author="Brian Balsamo",
    author_email="brian@brianbalsamo.com",
    packages=find_packages(
        exclude=[
        ]
    ),
    entry_points={
        'console_scripts': [
            'accession = accutil:launch',
        ]
    },
    include_package_data=True,
    url='https://github.com/bnbalsamo/accutil',
    dependency_links=[
        'https://github.com/bnbalsamo/pyqremis' +
        '/tarball/master#egg=pyqremis',
        'https://github.com/bnbalsamo/qremiser' +
        '/tarball/master#egg=qremiser',
    ],
    install_requires=[
        'requests>0',
        'requests-toolbelt',
        'pyqremis',
        'qremiser'
    ],
    tests_require=[
        'pytest'
    ],
    test_suite='tests'
)
