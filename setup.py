from pathlib import Path

from setuptools import find_packages
from setuptools import setup

from build.lib.mailjet_rest.utils.version import get_version


HERE = Path(Path(__file__).parent).resolve()
PACKAGE_NAME = "mailjet_rest"

# Dynamically calculate the version based on mailjet_rest.VERSION.
version = get_version()

setup(
    name=PACKAGE_NAME,
    author="starenka",
    author_email="starenka0@gmail.com",
    maintainer="Mailjet",
    maintainer_email="api@mailjet.com",
    version=version,
    download_url="https://github.com/mailjet/mailjet-apiv3-python/releases/" + version,
    url="https://github.com/mailjet/mailjet-apiv3-python",
    description=("Mailjet V3 API wrapper"),
    long_description=Path("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    classifiers=['Development Status :: 4 - Beta',
                 'Environment :: Console',
                 'Intended Audience :: Developers',
                 'License :: OSI Approved :: MIT License',
                 'Natural Language :: English',
                 'Operating System :: OS Independent',
                 'Programming Language :: Python :: 2.7',
                 'Programming Language :: Python :: 3.5',
                 'Programming Language :: Python :: 3.6',
                 'Topic :: Utilities'],
    license='MIT',
    keywords='Mailjet API v3 / v3.1 Python Wrapper',
    include_package_data=True,
    install_requires=["requests>=2.4.3"],
    tests_require=["unittest"],
    entry_points={},
    packages=find_packages(),
)
