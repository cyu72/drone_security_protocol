#include <routing/hashTree.hpp>

HashTree::TreeNode::TreeNode(const string& data, bool isHash) : left(nullptr), right(nullptr) { 
    if (isHash) {
        hash = data;
    } else {
        hash = hashString(data);
    }
}

string HashTree::TreeNode::hashString(const string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);
    return bytesToHexString(hash, SHA256_DIGEST_LENGTH);
}

string HashTree::hashNodes(const string& hash1, const string& hash2) {
    string combined = hash1 + hash2;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined.c_str(), combined.size(), hash);
    return bytesToHexString(hash, SHA256_DIGEST_LENGTH);
}

string HashTree::hashSelf(const string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);
    return bytesToHexString(hash, SHA256_DIGEST_LENGTH);
}

string HashTree::bytesToHexString(unsigned char* bytes, int length) {
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    return ss.str();
}

HashTree::HashTree(std::vector<string> hashesArray, int hopCount, string sourceAddr) {
    string lastElementHash = hashSelf(sourceAddr);
    
    if (hopCount == 1) {
        root = new TreeNode(lastElementHash, true);
        return;
    }

    int requiredLevels = std::ceil(std::log2(hopCount));
    TreeNode* rightSubtree = new TreeNode(lastElementHash, true);
    string currentHash = lastElementHash;
    
    for (int i = 1; i < requiredLevels; i++) {
        currentHash = hashNodes(currentHash, currentHash);
        TreeNode* newNode = new TreeNode(currentHash, true);
        newNode->setLeft(rightSubtree);
        rightSubtree = newNode;
    }

    TreeNode* leftSubtree = new TreeNode(hashesArray[1], true);
    root = new TreeNode(hashesArray[0], true);
    root->setLeft(leftSubtree);
    root->setRight(rightSubtree);
}

bool HashTree::verifyTree(string& recvHash) {
    return recvHash == root->hash;
}

void HashTree::addSelf(const string& droneID, const int& incomingHopCount) {
    /* Adds a new node to the tree. 
    Takes in self drone id and the hopCount after adding the currentNode*/
    int leafLevel = std::ceil(std::log2(incomingHopCount));
    int totalAvailableNodes = std::pow(2, leafLevel) / 2;
    
    if (incomingHopCount == 2) {
        root->left = new TreeNode(root->getHash(), true);
        root->right = new TreeNode(hashSelf(droneID), true);
        root->updateHash(hashNodes(root->left->getHash(), root->right->getHash()));
        return;
    }

    int n = incomingHopCount - 1;
    if ((n & (n - 1)) == 0) {
        TreeNode* newRoot = new TreeNode("", true);
        TreeNode* newRight = new TreeNode("", true);
        newRoot->left = root;
        newRoot->right = newRight;
        root = newRoot;
    }

    string finalHash = recalculate(root->right, totalAvailableNodes / 2,
                                 totalAvailableNodes + 1,
                                 totalAvailableNodes + (totalAvailableNodes / 2) + 1,
                                 leafLevel - 1, incomingHopCount, droneID);
    root->updateHash(hashNodes(root->left->getHash(), finalHash));
}

string HashTree::recalculate(TreeNode* node, const int& nodesAvail, const int& leftIndex,
                           const int& rightIndex, const int& leafLevel, const int& incomingHopCount,
                           const string& droneID) {
    /* Parameters: A node (starts with the root), (Int) leafLevel left to go in tree before we reach leaves
    Recursive function to recalculate a node, given that its children nodes have been updated
    Returns a string of the newly calculated hash*/
    if (!node || nodesAvail < 1 || leftIndex < 0 || rightIndex < leftIndex) {
        
        return node ? node->getHash() : "";
    }

    string newHash;
    bool isLeft = true;

    if (leafLevel > 1) {
        int nextNodesAvail = std::max(1, nodesAvail / 2);
        if (incomingHopCount >= rightIndex && rightIndex > 0) {
            if (!node->right) node->right = new TreeNode("", true);
            newHash = recalculate(node->right, nextNodesAvail,
                                leftIndex + nextNodesAvail, rightIndex,
                                leafLevel - 1, incomingHopCount, droneID);
            isLeft = false;
        } else {
            if (!node->left) node->left = new TreeNode("", true);
            newHash = recalculate(node->left, nextNodesAvail,
                                leftIndex, rightIndex - nextNodesAvail,
                                leafLevel - 1, incomingHopCount, droneID);
        }
    }

    if (leafLevel == 1) {
        newHash = hashSelf(droneID);
        if (incomingHopCount % 2 == 0) {
            node->setRight(new TreeNode(newHash, true));
            isLeft = false;
        } else {
            node->setLeft(new TreeNode(newHash, true));
        }
    }

    newHash = isLeft ? hashNodes(newHash, newHash) :
                      hashNodes(node->left ? node->left->getHash() : newHash, newHash);
    node->updateHash(newHash);
    return newHash;
}

std::vector<string> HashTree::toVector() {
    std::vector<string> hashes;
    hashes.push_back(root->hash);
    
    TreeNode* currNode = root;
    while (currNode) {
        if (currNode->left) {
            hashes.push_back(currNode->left->hash);
        }
        currNode = currNode->right;
    }
    
    return hashes;
}