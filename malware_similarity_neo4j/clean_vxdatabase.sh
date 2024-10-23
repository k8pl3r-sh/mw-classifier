#!/bin/bash
# Extract Families 7z

# Remove Papers directories
find . -type d -name "Paper" -exec rm -rf {} +
find . -type d -name "Papers" -exec rm -rf {} +

# Decompress all zip and 7z files
find . -type f -name "*.7z" -exec sh -c '7z e -p"infected" -y -o"$(dirname "{}")" "{}" && rm -f "{}"' \; # -y pour forcer à yes
# find . -type f -name "*.zip" -exec sh -c 'unzip -P "infected" -y -d "$(dirname "{}")" "{}" && rm -f "{}"' \;

# Malformatted filenames :
# find . -type f | grep -E '^[^_]*(_[^_]*){0,1}[^_]*$' | grep -v -e txt -e ioc
# ./WARP/WARP_sample/C0134285A276AB933E2A2B9B33B103CD

# Command to solve the issue
#find . -type f | grep -E '^[^_]*(_[^_]*){0,1}[^_]*$' | grep -v -e txt -e ioc | while read -r filepath; do \
#  find "$(dirname "$filepath")" -maxdepth 1 -name "$(basename "$filepath")" -exec bash -c ' \
#    for file; do \
#      dir=$(dirname "$file"); \
#      filename=$(basename "$file"); \
#      parent_folder=$(basename "$dir"); \
#      mv "$file" "$dir/${parent_folder}_$filename"; \
#    done' bash {} +; \
#done

# Rename files to add Family names followed by "_sample_" prefix
# Base directory where the traversal starts
base_dir="."

# Traverse through the directory structure
find "$base_dir" -type f | while read -r file; do
    # Extract the family name (immediately parent directory)
    family_name=$(basename "$(dirname "$(dirname "$file")")")
    echo "###########"
    full_path=$(realpath "$file")
    dir_path=$(dirname "$full_path")
    first_folder=$(echo "$dir_path" | awk -F'/' '{print $6}')
    # Use 'sample' instead of the actual folder name
    folder_prefix="sample"
    #echo $folder_prefix
    # Extract the original file name
    file_name=$(basename "$file")
    #echo $file_name
    # Construct the new file name
    new_file_name="${first_folder}_${folder_prefix}_${file_name}"
    #echo $new_file_name
    # Construct the new file path
    new_file_path="$(dirname "$file")/${new_file_name}"

    # Rename the file
    mv "$file" "$new_file_path"

    echo "Renamed '$file' to '$new_file_path'"
done

find . -depth -type d -name "* *" -exec bash -c 'mv "$0" "${0// /}"' {} \; # Remove spaces in directories names
find . -type f -name "* *" -exec bash -c 'mv "$0" "${0// /}"' {} \; # Remove spaces in files names

# Add an X to filenames starting with a number
find . -type f -name "* *" -exec bash -c '[[ $(basename "$0") =~ ^[0-9] ]] && mv "$0" "$(dirname "$0")/X$(basename "$0")"' {} \;
