#ifndef HASH_TREE_HPP
#define HASH_TREE_HPP
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <vector>
#include <iostream>
#include <openssl/sha.h>
#include <string>
#include <sstream>
#include <cmath>

using std::string;
using std::endl;
using std::cout;

/* Leaf Nodes are hashes of droneID. In other words, the leaf node IS NOT the droneID. */

class HashTree {
private:
    class TreeNode {  
        public:
            string hash;
            TreeNode *left;
            TreeNode *right;
            TreeNode(const string&, bool);
            ~TreeNode() {};

            string hashString(const string&);
            void setLeft(TreeNode *leftNode) { left = leftNode; }
            void setRight(TreeNode *rightNode){ right = rightNode; }
            string getHash() { return hash; }
            void updateHash(std::string hash) {this->hash = hash; }

    };
    string hashSelf(const string&);
    string hashNodes(const string&, const string&);
    string recalculate(TreeNode*, const int&, const int&, const int&, const int&, const int&, const string&);
    TreeNode *root;
    void setRoot(TreeNode* node) {this->root = node;}

public:
    // case1: first time init tree
    HashTree(const string& droneNum) {
        std::cout << "HashTree created" << std::endl;
        this->root = new TreeNode(droneNum, false);
    }

    // case2: along the path, we are rebuilding tree
    HashTree(std::vector<string> hashes, int hopCount, string sourceAddr);

    void deleteTree(TreeNode *node) {
        if (node->left != nullptr) {
            deleteTree(node->left);
        }
        if (node->right != nullptr) {
            deleteTree(node->right);
        }
        cout << "deleting node: " << node->hash << endl;
        delete node;
    }

    ~HashTree() {
        deleteTree(root);
    };

    void printTree(TreeNode* node){
        if (node->left != nullptr){
            printTree(node->left);
        }
        if (node->right != nullptr){
            printTree(node->right);
        }
        std::cout << "data: " << node->hash << std::endl;
    }

    bool verifyTree(string&);
    TreeNode* getRoot() { return root; }
    void addSelf(const string&, const int&);
    std::vector<string> toVector();
};

#endif