#!/bin/bash

check_python_version() {
    echo "[ + ] Checking Python version . . ."
    echo "[ $ ] python3 --version"

    MINIMUM_VERSION="3.5"
    PYTHON_VERSION=$(python3 --version 2>&1)

    echo "$PYTHON_VERSION"

    # This ensures the Python version is 3.5 or higher. https://regex101.com/
    VERSION_REGEX="^Python\ ((3\.[^0-4])|(3\.[1-9][0-9]+)|([4-9]+\.\d+))(.*)$"

    if [[ $PYTHON_VERSION =~ $VERSION_REGEX ]]; then
        echo "[ + ] Your Python version is compatible with Pacu."
    else
        echo "\\033[38;5;202m[ - ] Pacu requires Python to be installed at version $MINIMUM_VERSION or higher. Your version is: $PYTHON_VERSION"
        echo "Please install Python version $MINIMUM_VERSION or higher. \\033[38;5;33mhttps://www.python.org/downloads/\\033[38;5;00m"
        exit 1
    fi
}

install_pip_requirements() {
    echo "[ + ] Installing Pacu's Python package dependencies . . ."

    # Determine if we should PIP install with the "--user" flag
    ADDITIONAL_PIP_PARAMS=""
    ISSUE_WARNING_FOR_PIP_ROOT_INSTALL=1
    # If we are in a virtual environment OR if the effective user is root,
    # then installing with --user is unnecessary.
    # Note: in BASH, we should be able to reference $EUID instead of
    # running the `id' command ourselves, but this is not the case in many
    # other shells. Therefore, to ensure minimal difficulty for porting to
    # other shell variants in the future, I am calling `id' below for
    # retreiving the user's effective ID number. This should be compatible
    # with most, if not all, other shells.
    USERS_EFFECTIVE_ID=$(id --user)
    if [ -z "$VIRTUAL_ENV" ] && [ "$USERS_EFFECTIVE_ID" != "0" ]; then
        # Because $VIRTUAL_ENV is empty or not set, we can assume we are NOT
        # inside of a Python virtual environment.
        # We also know we are not root. Therefore, we will not have access to
        # the system's Python installation's site-packages location.
        # We should instead install with "--user" so the packages are
        # installed for the session user.
        ADDITIONAL_PIP_PARAMS="--user"
    elif [ "$USERS_EFFECTIVE_ID" == "0" ]; then
        # The installation script is being executed as root user.
        # While this will let us install the required packages, we should
        # consider issuing a warning to the user, because running PIP install
        # as root is generally discouraged and considered an unsafe practice.
        # It's not the best source discussing the issue, but you may reference
        # the following StackOverflow answer for more on this matter:
        # https://stackoverflow.com/a/21056000/2694511
        if [[ ! -z "$ISSUE_WARNING_FOR_PIP_ROOT_INSTALL" ]]; then
            echo "[ - ] It seems you are running this PIP installation as root."
            echo "[ - ] Given the audience for this application, it is assumed that you know what you are doing and have accepted these risks. Therefore, the installation shall proceed."
            echo "[ - ] However, if you were not aware of the risks of running PIP with root level permissions, then you should read up on the subject and keep these considerations in mind in the future."
        fi
    fi

    echo "[ $ ] pip3 install -r requirements.txt ${ADDITIONAL_PIP_PARAMS}"
    # Export variable so it is available to $(...), which is technically a
    # sub-shell.
    export $ADDITIONAL_PIP_PARAMS;
    PIP_OUTPUT=$(pip3 install -r requirements.txt $ADDITIONAL_PIP_PARAMS)
    PIP_ERROR_CODE=$?

    echo "$PIP_OUTPUT"

    if [ $PIP_ERROR_CODE = '0' ]; then
        echo "[ + ] Pip install finished. (exit $PIP_ERROR_CODE)"
    else
        echo "\\033[38;5;202m[ - ] Pip raised an error while installing Pacu's Python package dependencies."
        echo "All Python packages used by Pacu should be installed before pacu.py is run."
        echo "It may be helpful to try running \`pip install -r requirements.txt\` directly."
        echo "For assistance troubleshooting pip installation problems, please provide the"
        echo "developers with as much information about this error as possible, including all"
        echo "text output by install.sh. (exit $PIP_ERROR_CODE)\\033[38;5;00m"
        exit 1
    fi
}

check_python_version
install_pip_requirements
