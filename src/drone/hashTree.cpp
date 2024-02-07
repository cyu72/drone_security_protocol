#include "hashTree.hpp"

HashTree::TreeNode::TreeNode(const string& data, bool isHash) : left(nullptr), right(nullptr) { 
    if (isHash) {
        hash = data;
    } else {
        hash = hashString(data);
        cout << "hash: " << hash << endl;
    }
}

string HashTree::TreeNode::hashString(const string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)data.c_str(), data.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    cout << ss.str() << endl;
    return ss.str();
}

string HashTree::hashNodes(const string& hash1, const string& hash2) {
    /* Hashes two values together, returns hash as string.
    Currently uses SHA256, but can change to lighterweight one later on.  */

    std::string combined = hash1 + hash2;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)combined.c_str(), combined.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

string HashTree::hashSelf(const string& data) {
    /* Hashes the data, returns hash as string.
    Currently uses SHA256, but can change to lighterweight one later on.  */

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)data.c_str(), data.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

// case2: along the path, we are rebuilding tree
HashTree::HashTree(std::vector<string> hashesArray, int hopCount, string sourceAddr){
    int numElements = hashesArray.size();
    string lastCalculatedHash;
    string lastElementHash;
    TreeNode *currNode;

    if (hopCount % 2 == 0) { // if hopCount is even, hash last with previous source addr hash to get parent node
        lastElementHash = hashSelf(sourceAddr);
        lastCalculatedHash = hashNodes(hashesArray[numElements - 1], lastElementHash);
        currNode = new TreeNode(lastCalculatedHash, true);
        currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
        currNode->setRight(new TreeNode(lastCalculatedHash, true));
    } else if (hopCount == 1) { // edgecase
        lastElementHash = hashSelf(sourceAddr);
        lastCalculatedHash = hashNodes(lastElementHash, hashesArray[numElements - 1]);
        currNode = new TreeNode(lastCalculatedHash, true);
        currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
        currNode->setRight(new TreeNode(lastElementHash, true));
    } else {
        lastElementHash = hashSelf(sourceAddr);
        lastCalculatedHash = hashNodes(lastElementHash, lastElementHash);
        currNode = new TreeNode(hashesArray[numElements - 1], true);
        currNode->setLeft(new TreeNode(lastCalculatedHash, true));
    }

    int i = numElements - 2;
    TreeNode *parentNode;
    while (i > 0){
        lastCalculatedHash = hashNodes(hashesArray[i], lastCalculatedHash);
        parentNode = new TreeNode(lastCalculatedHash, true);
        parentNode->setLeft(new TreeNode(hashesArray[i], true));
        parentNode->setRight(currNode);
        currNode = parentNode;
        i--;
    }
    root = currNode;
    // printTree(root);
    /* Pseudocode (This is not rebuilding the tree, we are simply reshahing to check the root node here, we prolly dont want to do that here and instead just rebuild the tree)
    lastCalculatedHash = if hopCount is odd, hash last element with itself to get parent node
    lastCalculatedHash = if hopCount is even, hash last with previous source addr hash to get parent node
    while currElementInHashArray != firstElement (we start from the second to last element)
        lastCalculatedHash = Hash[currElementInHashArray || lastCalculatedHash]
    if lastCalcualtedHash == root
        choose nodes to send and proceed with rreq/rrep action
    else
        delete tree and throw away packet

    */

    std::cout << "HashTree created" << std::endl;
}