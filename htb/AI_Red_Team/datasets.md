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

## Handling Invalid Entries
- Dropping Invalid Entires
** This is the most straightforward approach and simply discards any entries with an error.
** Generally preferred when data accuracy is paramount, and the loss of some data doesn't significantly compromise the overall analysis.
** Not always feasible with a small dataset or invalid entries consititute a significant amount of the data.

- Imputing missing values  
** `imputing` is the process of replacing missing or invalid values in the dataset with estimated values
