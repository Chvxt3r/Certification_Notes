# Definition
Structured collections of data used for analysis and model training.

## Forms
* Tabular Data: Data organized into tables with rows and columns, like a spreadsheet or database
* Image Data: Set of images represented numerically as a pixel array
* Text Data: Unstructured data composed of sentences, paragraphs, or full documents
* Time SEries Data: Sequential data points collected over time, emphasizing temporal patterns

## Quality
* High- Quality datasets produce more accurate models (garbage in/garbage out)
* Carefully curated datasets enable models to generalize more effectively to unseen data. Minimized overfitting (Making the model too specific)
* Well prepared data reduces training time and computational demands
* Reliable datasets lead to trustworthy insights and decisions.

## Attributes of a "Good" Dataset
|Attribute|Description|Example|
|---------|-----------|-------|
|`Relevance`|The data should be relevant to the problem at hand. Irrelevant data can introduce noise and reduce model performance.|Text data from social media posts is more relevant than stock market prices for a sentiment analysis task.|
|`Completeness`|The dataset should have minimal missing values. Missing data can lead to biased models and incorrect predictions.|Techniques like imputation can handle missing values, but it's best to start with a complete dataset if possible.|
|`Consistency`|Data should be consistent in format and structure. Inconsistencies can cause errors during preprocessing and model training.|Ensure that date formats are uniform across the dataset (e.g.,`YYYY-MM-DD`).|
|`Quality`|The data should be accurate and free from errors. Errors can arise from data collection, entry, or transmission issues.|Data validation and verification processes can help ensure data quality.|
|`Representativeness`|The dataset should be representative of the population it aims to model. A biased or unrepresentative dataset can lead to biased models.|A facial recognition system's dataset should include a diverse range of faces from different ethnicities, ages, and genders.|
|`Balance`|The dataset should be balanced, especially for classification tasks. Imbalanced datasets can lead to biased models that perform poorly on minority classes.|Techniques like oversampling, undersampling, or generating synthetic data can help balance the dataset.|
|`Size`|The dataset should be large enough to capture the complexity of the problem. Small datasets may not provide enough information for the model to learn effectively.|However, large datasets can also be computationally expensive and require more powerful hardware.|

## Dataset Challenges and Considerations
Note potential difficulties such as:
* mix of numerical or categorical data
* Missing value and invalid entries, requiring cleaning
* numeric columns containing strings, which will need to be converted or moved
* Unknown values that must be standardized or otherwise addressed.

## Evaluating a Dataset
- Loading into a pandas dataframe makes inspecting, manipulating, and preparing the dataset more straightforward.
```python
import pandas as pd

# Load the dataset
data = pd.read_csv("./demo_dataset.csv")
```
:warning: This code assumes we are working with a `.csv`. Alter the code to fit your data

- Exploring - Now we can evaluate the dataset to find and correct any anomolies
```python
# Display the first few ros
print(data.head())

# Get a summary of the column data types and non-null counts
print(data.info())

# Identify Columns with missing values
print(data.isnull().sum())
```
-- The `info()` method reveals the datasets shape, column names, data types, and how many entries are present for each column.

# Data Preprocessing
Transforms the raw data into a suitable format for machine learning.
* Data Cleaning: Fixing missing values, removing duplicates, and smoothing noisy data.
* Data Transoformation: Normalizing, encoding, scaling, and reducing data.
* Data Integration: Merging and aggregating data from multiple sources
* Data Formatting: Converting data types and reshaping data structures.

## Data Cleaning
### Handling Invalid Entries
- Dropping Invalid Entires  
** This is the most straightforward approach and simply discards any entries with an error.  
** Generally preferred when data accuracy is paramount, and the loss of some data doesn't significantly compromise the overall analysis.  
** Not always feasible with a small dataset or invalid entries consititute a significant amount of the data.  

- Imputing missing values  
** `imputing` is the process of replacing missing or invalid values in the dataset with estimated values.  
** For basic numeric columns, simple methods such as median or mean work best.  
** For categorical columns, use the most frequent value.  
** `SimpleImputer` can be used for simple scenarios, but more sophisticated datasets may need `KNNImputer` or `IterativeImputer`.  
** Once imputation is done, apply domain knowledge to solve any entries still missing.

## Data Transformation - Improving the representation and distribution of features
### Encoding - Converting categorical values into numeric form
- `OneHotEncoder` - for binary indicator features that represent each category seperately.  
** Takes a categorical feature(like "color") and converts it into a set of new binary featurs.  
** ex. Color contains red, green, and blue. One-hot encoding would remove Color, and create color_red, color_blue, and color_green, set to 1 or 0 depending on the original color.  
** prevents models from misinterpreting category values as numeric hierarchies, but can increase the number of featurs if the category has alot of unique values.
- `LabelEncoder` - for integer codes (may imply unintended order).
- `HashingEncoder` - or frequency-based methods to handle high-cardinality featurs and control feature space size.
> After encoding, verify that the transformed features are meaningful and do not introduce artificial ordering.  
### Handling Skewed Data
- Skew occurs when the values are unvevenly distributed, often clustering near one end, with a few outliers stretching out the distribution
- Scaling the skewed values helps model better capture patterns in the data.
- Common scaling transform is to apply a `log` transform to compress large values more than small ones, resulting in a more balanced distribution and reduce the impact of outliers.  
### Data Splitting
- Split the dataset into 3 subsets (Training, Validation, and testing)  
** Training Set - Used to fit the model. Typicall 60-80% of the entire dataset  
** Validation Set - Used for tuning hyperparamters and model selection. 10-20% of the entire dataset
** Test Set - Used after model selections and turning are complete. Remaining 10-20% of the dataset  

## Evaluation Metrics
### Accuracy
- Proportion of correct predictions out of all predictions made.  
** Computed as `(true positives + true negatives) / (all instances)`.  
** Can be misleading in cases of class imbalance  

### Precision
- Measures how often the models predicted positives are truly positive.  
** Computed as `true positives / (true positives + false positives)`.  
** High precision reduces false alarms

### Recall
- Measures the models ability to identify all positive instances.  
** Computed as `true positives / (true positives + false negatives).  
** High recall reduces risk of missing critical cases

### F1-score
- harmonic mean of precision and recall. Higher score indicates balance of precision and recall.  
** Computed as `2 * (precision * recall) / (precision + recall).  
** Useful for tasks involving class imbalance.

