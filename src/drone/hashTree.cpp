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

/*HashesArray[root, leftNode, .... n - 1]*/
HashTree::HashTree(std::vector<string> hashesArray, int hopCount, string sourceAddr){
    /*Case 2: Along the path, we are rebuilding the tree.
    Arguments:
    1) The array of of hashes
    2) Current HopCount
    3) Address this message was recieved from 
    */
    int numElements = hashesArray.size();
    string lastCalculatedHash;
    string lastElementHash;
    TreeNode *currNode;

    if (hopCount == 1){ // edgecase for constructing from one hash
        lastElementHash = hashSelf(sourceAddr);
        lastCalculatedHash = hashNodes(lastElementHash, lastElementHash);
        currNode = new TreeNode(lastCalculatedHash, true);
        currNode->setLeft(new TreeNode(lastElementHash, true));
        root = currNode;
    } else if (hopCount == 2) { // edgecase for constructing from two hashes
        lastElementHash = hashSelf(sourceAddr);
        lastCalculatedHash = hashNodes(hashesArray[1], lastElementHash);
        currNode = new TreeNode(lastCalculatedHash, true);
        root = currNode;
        currNode = new TreeNode(hashesArray[1], true);
        root->setLeft(currNode);
        currNode = new TreeNode(lastElementHash, true);
        root->setRight(currNode);
    } else if ((numElements == 2 || numElements == 3) && (( ( (hopCount - 1) % 4 == 0) ) || ((hopCount - 2) % 4 == 0) ) ){ // edgecase for constructing leftmost subtree
        lastElementHash = hashSelf(sourceAddr);
        if (numElements == 2){
            lastCalculatedHash = hashNodes(lastElementHash, lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(lastElementHash, true));
        } else {
            lastCalculatedHash = hashNodes(hashesArray[2], lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(hashesArray[2], true));
            currNode->setRight(new TreeNode(lastElementHash, true));
        }

        
        TreeNode *prev = currNode;
        int levels = std::ceil(std::log2(hopCount));
        while (levels > 2){ // We skip past the leaf level and keep going until first level
            lastCalculatedHash = hashNodes(lastCalculatedHash, lastCalculatedHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(prev);
            prev = currNode;
            levels--;
        }

        lastCalculatedHash = hashNodes(hashesArray[1], lastCalculatedHash);
        currNode = new TreeNode(lastCalculatedHash, true);
        currNode->setLeft(new TreeNode(hashesArray[1], true));
        currNode->setRight(prev);
        root = currNode;
    } else if ((hopCount < 5) && ((hopCount % 4 == 0) || ((hopCount + 1) % 4 == 0))){ // edgecase for constructing rightmost subtree
        lastElementHash = hashSelf(sourceAddr);
        if (hopCount % 4 == 0){
            lastCalculatedHash = hashNodes(hashesArray[numElements - 1], lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setRight(new TreeNode(lastElementHash, true)); // do not require these to be added, can be removed for optimization
            currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
            numElements--;
        } else {
            lastCalculatedHash = hashNodes(lastElementHash, lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(lastElementHash, true));
        }

        TreeNode *prev = currNode;
        int levels = std::ceil(std::log2(hopCount));
        while (levels > 1){
            lastCalculatedHash = hashNodes(hashesArray[numElements - 1], lastCalculatedHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setRight(prev);
            currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
            prev = currNode;
            levels--;
            numElements--;
        }
        root = currNode;

    } else { // generalized case
        TreeNode* prev;
        int prevLevel = hopCount;
        lastElementHash = hashSelf(sourceAddr);
        if (prevLevel % 2 == 1){
            lastCalculatedHash = hashNodes(lastElementHash, lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(lastElementHash, true));
        } else {
            lastCalculatedHash = hashNodes(hashesArray[numElements - 1], lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
            currNode->setRight(new TreeNode(lastElementHash, true));
            numElements--;
        }
        prev = currNode;
        
        int levels = std::ceil(std::log2(hopCount));
        prevLevel = std::ceil((prevLevel / 2.0));
        while (levels > 2){ // skip leaf & root
            if (prevLevel % 2 == 1){
                lastCalculatedHash = hashNodes(lastCalculatedHash, lastCalculatedHash);
                currNode = new TreeNode(lastCalculatedHash, true);
                currNode->setLeft(prev);
            } else {
                cout << prevLevel << std::endl;
                lastCalculatedHash = hashNodes(hashesArray[numElements - 1], lastCalculatedHash);
                currNode = new TreeNode(lastCalculatedHash, true);
                currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
                currNode->setRight(prev);
                numElements--;
            }
            prev = currNode;
            levels--;
            prevLevel = std::ceil((prevLevel / 2));
        }
        // root case
        lastCalculatedHash = hashNodes(hashesArray[1], lastCalculatedHash);
        root = new TreeNode(lastCalculatedHash, true);
        root->setLeft(new TreeNode(hashesArray[1], true));
        root->setRight(prev);

        /* 
        function to determine if subtree is left or right(hopCount):
            log2(hopCount) = n
            2^n / 2 = y
            If hopCount > (y + y/2): in right subtree
            else in left subtree
            return true if in right, false if in left
        
        while level > 1:
        Determine what subtree current element is in
            if left: hash self
            if right: hash with n, where n is the last element in the hasharray
        Move up one level, determine that subtree
            if left: hash self
            if right: hash with n - 1, where n is second to last element
        etc, etc.*/
    }

    std::cout << "HashTree created" << std::endl;
}

bool HashTree::verifyTree(string& recvHash){
    /* Verifies the tree via checking root hash with calculated root. */
    if (recvHash == root->hash){
        return true;
    }
    return false;
}

void HashTree::addSelf(string& droneName){

}

std::vector<string> HashTree::toVector(){
    /*Returns a vector of only the elements required to rebuild the tree*/
    std::vector<string> hashes;
    hashes.push_back(root->hash);
    TreeNode* currNode = root;
    TreeNode* leftNode;
    while(currNode->left != nullptr && currNode->right != nullptr){
        leftNode = currNode->left;
        hashes.push_back(leftNode->hash);
        currNode = currNode->right;
    } // Need to make the case where the right node is null (we had to duplicate nodes to finish tree)

    for (const auto& hash : hashes) {
        std::cout << hash << std::endl;
    }

    return hashes;
}