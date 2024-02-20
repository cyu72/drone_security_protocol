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

    if (hopCount % 2 == 0) { // if hopCount is even, hash last with previous source addr hash to get parent node
        lastElementHash = hashSelf(sourceAddr);
        lastCalculatedHash = hashNodes(hashesArray[0], lastElementHash);
        currNode = new TreeNode(lastCalculatedHash, true);
        currNode->setLeft(new TreeNode(hashesArray[0], true));
        currNode->setRight(new TreeNode(lastElementHash, true));
    } else if (hopCount == 1) { // edgecase for constructing from one hash
        lastElementHash = hashSelf(sourceAddr);
        currNode = new TreeNode(lastElementHash, true);
    } else if (hopCount % 4 == 1) { // edgecase: odd but leaf is the first in the subtree
        if (hopCount % 8 == 1){ // we are at the first element of the new subtree
            TreeNode *parent;
            int numTimesHashed = (hopCount / 8) + 2;
            lastElementHash = hashSelf(sourceAddr);
            currNode = new TreeNode(lastElementHash, true);
            lastCalculatedHash = hashNodes(lastElementHash, lastElementHash); // hash of droneID (leaf)
            parent = new TreeNode(lastCalculatedHash, true);
            parent->setLeft(currNode);
            currNode = parent;

            for (int i = 1; i < numTimesHashed; i++){
                lastCalculatedHash = hashNodes(lastCalculatedHash, lastCalculatedHash);
                parent = new TreeNode(lastCalculatedHash, true);
                parent->setLeft(currNode);
                currNode = parent;
            }

            lastCalculatedHash = hashNodes(hashesArray[1], lastCalculatedHash); // always get leftmost hash
            parent = new TreeNode(lastCalculatedHash, true);
            parent->setLeft(new TreeNode(hashesArray[1], true));
            parent->setRight(currNode);
            root = parent;
            return;
        }

        // TODO: Case where we are only a partly empty subtree (13)

    } else { // edgeCase: odd but leaf is already part of subtree
        lastElementHash = hashSelf(sourceAddr);
        lastCalculatedHash = hashNodes(lastElementHash, lastElementHash);
        currNode = new TreeNode(lastCalculatedHash, true);
        currNode->setLeft(new TreeNode(lastElementHash, true));
        TreeNode *prevNode = currNode;

        lastCalculatedHash = hashNodes(hashesArray[0], lastCalculatedHash);
        currNode = new TreeNode(lastCalculatedHash, true);
        currNode->setLeft(new TreeNode(hashesArray[0], true));
        currNode->setRight(prevNode);
    }

    int i = 1;
    TreeNode *parentNode;
    while (i < numElements - 1){
        lastCalculatedHash = hashNodes(hashesArray[i], lastCalculatedHash);
        parentNode = new TreeNode(lastCalculatedHash, true);
        parentNode->setLeft(new TreeNode(hashesArray[i], true));
        parentNode->setRight(currNode);
        currNode = parentNode;
        i++;
    }
    root = currNode;
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