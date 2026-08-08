# Network Anomaly Detection
Anomaly detection identifies data points that deviate significantly from the norm. Such anomalies indicate malicious activity, network intruders, or other security issues.

## Random Forests
Random Forest is an ensemble machine learning algorithim that builds multiple decision trees and aggregates their predictions. In classification, each tree votes and and the classification receiving the most votes is chosen. In regression tasks, the final prediction is the average of the individual tree outputs.

Robust performance in high-dimension datasets and reduced overfitting.

### Key Concepts
1. Bootstrapping: Multiple subsets of the training data are created via sampling with replacement. Each subset trains a separate decision tree.
2. Tree Construction: For each tree, a random subset of features is considered at every split, ensuring diversity and reducing correlations among trees.
3. Voting: After all trees are trained, classification involves majority voting, while regression involves averageing predictions.

## Random Forests for Anomaly Detection
- Random Forests are training stricly on data representing normal conditions. No anomolous data.
- New unseen datapoints are evaluated against the normal conditions.
