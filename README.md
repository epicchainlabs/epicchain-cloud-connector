# EpicChain Cloud Connector

[<img src="https://rclone.org/img/logo_on_light__horizontal_color.svg" width="50%" alt="rclone logo">](https://rclone.org/#gh-light-mode-only)
[<img src="https://rclone.org/img/logo_on_dark__horizontal_color.svg" width="50%" alt="rclone logo">](https://rclone.org/#gh-dark-mode-only)

[Website](https://rclone.org) | [Documentation](https://rclone.org/docs/) | [Download](https://rclone.org/downloads/) | [Contributing](CONTRIBUTING.md) | [Changelog](https://rclone.org/changelog/) | [Installation](https://rclone.org/install/) | [Forum](https://forum.rclone.org/)

[![Build Status](https://github.com/rclone/rclone/workflows/build/badge.svg)](https://github.com/rclone/rclone/actions?query=workflow%3Abuild)
[![Go Report Card](https://goreportcard.com/badge/github.com/rclone/rclone)](https://goreportcard.com/report/github.com/rclone/rclone)
[![GoDoc](https://godoc.org/github.com/rclone/rclone?status.svg)](https://godoc.org/github.com/rclone/rclone)
[![Docker Pulls](https://img.shields.io/docker/pulls/rclone/rclone)](https://hub.docker.com/r/rclone/rclone)

## Introduction

**EpicChain Cloud Connector** is an advanced synchronization tool designed to seamlessly integrate EpicChain with various cloud storage providers. Inspired by the well-established Rclone tool, EpicChain Cloud Connector facilitates efficient file and directory synchronization, providing users with powerful capabilities to manage their data across multiple cloud storage platforms. 

Whether you need to backup files, synchronize directories, or perform complex data migrations, EpicChain Cloud Connector offers a robust command-line interface to streamline these tasks. Its versatility in supporting numerous cloud storage services makes it an invaluable tool for both individual users and enterprises.

## Key Features

### Extensive Cloud Storage Support

EpicChain Cloud Connector supports a broad range of cloud storage providers, allowing you to manage and synchronize data across diverse platforms. Key providers include:

- **Google Drive**: Sync and manage files with Google Drive, ensuring seamless integration with your Google account.
- **Amazon S3**: Interface with Amazon's scalable cloud storage service, ideal for large-scale data management.
- **Dropbox**: Integrate with Dropbox for easy file sharing and synchronization across devices.
- **Backblaze B2**: Utilize Backblaze B2 for cost-effective cloud storage solutions.
- **Microsoft OneDrive**: Sync your files with Microsoft OneDrive, leveraging its integration with Microsoft Office.

Additional supported providers include Box, Dropbox, Google Cloud Storage, Yandex Disk, and many others. For a full list of supported providers and their specific features, visit the [EpicChain Cloud Connector storage providers page](https://rclone.org/overview/).

### Comprehensive Sync Modes

EpicChain Cloud Connector offers various synchronization modes to cater to different needs:

- **Copy Mode**: Efficiently copy new or changed files from source to destination.
- **Sync Mode**: Ensure the destination is identical to the source by synchronizing files in one direction.
- **Check Mode**: Verify that files in the source and destination match by checking their hashes.

### Advanced Features

- **File Integrity Verification**: MD5/SHA-1 hashes are used to ensure the integrity of files during transfers.
- **Timestamp Preservation**: Original file timestamps are maintained, preserving metadata across different storage systems.
- **Compression**: Optional file compression is supported, allowing for reduced storage space and faster transfers.
- **Encryption**: Secure your data with optional encryption, protecting sensitive information during storage and transit.
- **Multi-threaded Downloads**: Accelerate file transfers with multi-threading, enhancing performance and efficiency.

## Installation and Setup

### Installation

To install EpicChain Cloud Connector, follow these steps:

1. **Download and Install**:
   Visit the [installation page](https://rclone.org/install/) on the EpicChain Cloud Connector website for detailed instructions on downloading and installing the tool for your operating system.

2. **Build from Source**:
   If you prefer to build the tool from source, clone the repository and run the build script:
   ```bash
   git clone https://github.com/epicchain/epicchain-cloud-connector.git
   cd epicchain-cloud-connector
   npm install
   bash build.sh
   ```

### Configuration

1. **Configure Cloud Providers**:
   Edit the configuration files to set up connections with your cloud storage providers. Configuration files are located in the `config` directory, typically named `mainnet.json` and `testnet.json`.

2. **Manage Endpoints**:
   Modify the endpoint configurations directly in these JSON files. This allows you to specify and update the cloud storage endpoints you wish to use.

3. **Flag Icons**:
   Each cloud provider endpoint has a corresponding locale property. Obtain the SVG flag icons from [Flag Icon CSS](https://github.com/lipis/flag-icon-css/tree/master/flags/1x1), adjust them as needed, and add them to `/src/assets/icons`.

### Running the Connector

To execute EpicChain Cloud Connector, use the command line with the appropriate configuration file:

```bash
./epicchain-cloud-connector -c config.yaml
```

Alternatively, set the environment variable to specify the configuration file:

```bash
EPICCHAIN_CLOUD_CONNECTOR_CONFIG=config.yaml ./epicchain-cloud-connector
```

## Deployment

EpicChain Cloud Connector can be hosted on GitHub Pages. Updates to the website are managed via the `gh-pages` branch, and GitHub Actions automate the deployment process.

To deploy:

1. **Push Changes**: Commit and push changes to the `gh-pages` branch.
2. **Automatic Deployment**: CI (GitHub Actions) will handle the deployment to [monitor.epicchain.org](https://monitor.epicchain.org).

## Troubleshooting and FAQ

### Common Issues

- **Endpoint Accessibility**: If an endpoint is not accessible, you can use EpicChain Cloud Connector to determine its status and decide which endpoint is currently available.
- **Sync Status**: Verify if an endpoint is fully synced to avoid issues with outdated transactions or data inconsistencies.

### Feature Requests

If you have ideas for new features or improvements, please submit them via the [Issues](https://github.com/epicchain/epicchain-cloud-connector/issues) section of the repository. We welcome contributions from the community to enhance the tool's functionality and performance.

## Contribution

Contributions are highly encouraged! To contribute to the EpicChain Cloud Connector:

1. **Fork the Repository**: Create a personal fork of the repository on GitHub.
2. **Make Changes**: Implement your changes or improvements.
3. **Submit a Pull Request**: Open a pull request to merge your changes into the main repository.

For detailed guidelines, refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file in the repository.

## License

EpicChain Cloud Connector is licensed under the MIT License. For full licensing details, see the [COPYING file](COPYING) included with the source code.
