#!/usr/bin/env python3
import argparse
import os
import subprocess


def main():
    parser = argparse.ArgumentParser(description="Build HexRaysCodeXplorer plugin")
    parser.add_argument("--ida", required=True, help="Path to IDA SDK")
    parser.add_argument("--hexrays", required=True, help="Path to HexRays SDK")
    parser.add_argument("--build-dir", default="build", help="Directory for build files")
    parser.add_argument("--config", default="Release", help="Build type")
    args = parser.parse_args()

    build_dir = os.path.abspath(args.build_dir)
    os.makedirs(build_dir, exist_ok=True)

    cmake_cmd = [
        "cmake",
        "..",
        f"-DIdaSdk_ROOT_DIR={args.ida}",
        f"-DHexRaysSdk_ROOT_DIR={args.hexrays}",
    ]
    subprocess.check_call(cmake_cmd, cwd=build_dir)

    build_cmd = ["cmake", "--build", ".", "--config", args.config]
    subprocess.check_call(build_cmd, cwd=build_dir)


if __name__ == "__main__":
    main()
