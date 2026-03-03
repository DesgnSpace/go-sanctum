#!/bin/bash
set -e

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: ./release.sh <version>"
    echo "Example: ./release.sh 0.1.1"
    exit 1
fi

MODULES=()
for dir in */; do
    if [ -f "${dir}go.mod" ]; then
        MODULES+=("${dir%/}")
    fi
done

echo "==> Releasing v${VERSION}"
echo ""

# Step 1: Tag and push the root module first
echo "Step 1: Tagging root module v${VERSION}..."
git tag -f "v${VERSION}"
git push origin "v${VERSION}" --force
echo "  Pushed v${VERSION} — waiting for Go proxy..."
sleep 5

# Step 2: Update submodule go.mod files
echo ""
echo "Step 2: Updating submodule go.mod files..."
for module in "${MODULES[@]}"; do
    modfile="${module}/go.mod"

    sed -i '' "s|github.com/desgnspace/go-sanctum v.*|github.com/desgnspace/go-sanctum v${VERSION}|" "$modfile"
    sed -i '' '/^replace github.com\/desgnspace\/go-sanctum/d' "$modfile"

    cd "$module"
    GONOSUMCHECK=* GOFLAGS=-mod=mod go mod tidy 2>/dev/null || true
    cd ..

    echo "  Updated ${modfile}"
done

# Step 3: Commit the submodule changes
echo ""
echo "Step 3: Committing submodule updates..."
git add -A
git commit -m "chore: update submodules for v${VERSION}"

# Step 4: Re-tag root to include submodule commit, tag submodules
echo ""
echo "Step 4: Tagging all modules..."
git tag -f "v${VERSION}"
for module in "${MODULES[@]}"; do
    git tag -f "${module}/v${VERSION}"
    echo "  Tagged ${module}/v${VERSION}"
done

# Step 5: Push everything
echo ""
echo "Step 5: Pushing..."
TAGS=("v${VERSION}")
for module in "${MODULES[@]}"; do
    TAGS+=("${module}/v${VERSION}")
done

git push origin main --force-with-lease
git push origin "${TAGS[@]}" --force

echo ""
echo "Released v${VERSION} with submodules: ${MODULES[*]}"
