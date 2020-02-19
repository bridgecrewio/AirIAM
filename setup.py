import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='AirIAM',
    version='0.1.0',
    url='https://github.com/bridgecrewio/AirIAM',
    license='Apache 2.0',
    author='Bridgecrew',
    author_email='support@bridgecrew.io',
    description='From an AWS IAM mess to an orderly terraform-based IAM',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security',
        'Topic :: Software Development :: Build Tools'
    ],
    python_requires='>=3.7',
)
