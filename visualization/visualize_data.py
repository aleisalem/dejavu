#!/usr/bin/python

from dejavu.utils.data import *
from dejavu.utils.graphics import *
from dejavu.utils.misc import *

import numpy as np
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA
from scipy.cluster.hierarchy import dendrogram

from matplotlib import pyplot as plt
import plotly.plotly as py
from plotly.offline import plot, iplot
from plotly.graph_objs import *


RGB = ["#ff4136", "#3d9970", "#ff851b", "#6baed6", "#808389", "#48494c"] # Normal colors


def plotDendrogram(model):
    """
    Authors: Mathew Kallada
    License: BSD 3 clause
    =========================================
    Plot Hierarachical Clustering Dendrogram 
    =========================================
    This example plots the corresponding dendrogram of a hierarchical clustering
    using AgglomerativeClustering and the dendrogram method available in scipy.
    """
    try:
        # Children of hierarchical clustering
        children = model.children_
        # Distances between each pair of children
        # Since we don't have this information, we can use a uniform one for plotting
        distance = np.arange(children.shape[0])
        # The number of observations contained in each cluster level
        no_of_observations = np.arange(2, children.shape[0]+2)
        # Create linkage matrix and then plot the dendrogram
        linkage_matrix = np.column_stack([children, distance, no_of_observations]).astype(float)
        # Plot the corresponding dendrogram
        plt.title('Hierarchical Clustering Dendrogram')
        dendrogram(linkage_matrix)
        #plot_dendrogram(model, labels=model.labels_)
        plt.show()

    except Exception as e:
        prettyPrintError(e)
        return False

    return True

def reduceAndVisualize(X, y, dim=2, reductionAlgorithm="tsne", figSize=(1024,1024), figTitle="Data visualization", appNames=[], appTypes=[], plottingTool="matplotlib"):
    """
    Generates a scatter plot using "plotly" after projecting the data points into <dim>-dimensionality using tSNE or PCA
    :param X: The matrix containing the feature vectors
    :type X: list
    :param y: The labels of the feature vectors
    :type y: list
    :param dim: The target dimensionality to project the feature vectors to (default=2)
    :type dim: int
    :param reductionAlgorithm: The algorithm to use for dimensionality reduction
    :type reductionAlgorithm: str
    :param figSize: The size of the figure
    :type figSize: tuple (of ints)
    :param figTitle: The title of the figure and the name of the resulting HTML file
    :type figTitle: str
    :param appNames: The names of apps to be used as tooltips for each data point. Assumed to match one-to-one with the feature vectors in X
    :type appNames: list of str
    :param plottingTool: The tool to use in plotting the reduced points (i.e., default: matplotlib or plotly)
    :type plottingTool: str
    :return: A bool depicting the success/failure of the operaiton
    """
    try:
        # Prepare data
        X, y = np.array(X), np.array(y)
        # Build model
        reductionModel = TSNE(n_components=dim) if reductionAlgorithm == "tsne" else PCA(n_components=dim)
        # Apply transformation
        prettyPrint("Projecting %s feature vectors of dimensionality %s into %s-d" % (X.shape[0], X.shape[1], dim))
        X_new = reductionModel.fit_transform(X)
        # Generate a scatter plot
        prettyPrint("Populating the traces for malware and goodware")
        traceCount = max(y)+1
        appTypes = appTypes if len(appTypes) > 0 else ["Unknown"]*traceCount
        # Create traces for the scatter plot 
        prettyPrint("Creating a scatter plot")

        if plottingTool == "matplotlib":
            if dim == 3:
                prettyPrint("Only 2-dimensional plots are currently supported for \"matplotlib\"", "warning")
                return False
            else:
                x1_mal, x1_good, x2_mal, x2_good = [], [], [], []
                for index in range(len(X)):
                    if y[index] == 1:
                        x1_mal.append(X_new[index][0])
                        x2_mal.append(X_new[index][1])
                    else:
                        x1_good.append(X_new[index][0])
                        x2_good.append(X_new[index][1])
                #print len(x1_mal), len(x2_mal)
                #print len(x1_good), len(x2_good)
                fig = plt.figure()
                plt.scatter(x1_good, x2_good, c=RGB[1], alpha=1.0, marker='o', label="Goodware")
                plt.scatter(x1_mal, x2_mal, c=RGB[0], alpha=1.0, marker='^', label="Malware")
                plt.xlabel("x1")
                plt.ylabel("x2")
                plt.tick_params(
                    axis='x',          # changes apply to the x-axis
                    which='both',      # both major and minor ticks are affected
                    bottom=True,       # ticks along the bottom edge are on
                    top=False,         # ticks along the top edge are off
                    labelbottom=False)
                plt.tick_params(
                    axis='y',          # changes apply to the y-axis
                    which='both',      # both major and minor ticks are affected
                    left=True,         # ticks along the left edge are on
                    top=False,         # ticks along the top edge are off
                    labelleft=False)
                plt.legend(loc='best')
                #plt.show()
    
                plt.savefig('Visualization_%s.pdf' % figTitle.replace(" ", "_").lower())
                plt.savefig('Visualization_%s.pgf' % figTitle.replace(" ", "_").lower())
                plt.close(fig)


        elif plottingTool == "plotly":
            allTraces = {}
            # Build traces
            for i in range(traceCount):
                allTraces[i] = []
                for j in range(len(X_new)):
                    if y[j] == i:
                        if dim == 2:
                            allTraces[i].append((appNames[j], X_new[j][0], X_new[j][1]))
                        if dim == 3:
                            allTraces[i].append((appNames[j], X_new[j][0], X_new[j][1], X_new[j][2]))
                    
            # Populate Scatters
            allScatters = []
            for i in range(traceCount):            
                if dim == 2:
                    allScatters.append(
                             Scatter(x=[x[1] for x in allTraces[i]],
                             y=[x[2] for x in allTraces[i]],
                             mode='markers',
                             name=appTypes[i],
                             marker=Marker(symbol='dot',
                                 size=6,
                                 color=RGB[i],
                                 opacity=0.75,
                                 line=Line(width=2.0)
                                 ),
                   hoverinfo='text',
                   text=[x[0] for x in allTraces[i]]
                   ))
                elif dim == 3:
                    allScatters.append(
                             Scatter3d(x=[x[1] for x in allTraces[i]],
                             y=[x[2] for x in allTraces[i]],
                             z=[x[3] for x in allTraces[i]],
                             mode='markers',
                             name=appTypes[i],
                             marker=Marker(symbol='dot',
                                 size=6,
                                 color=RGB[i],
                                 opacity=0.75,
                                 line=Line(width=2.0)
                                 ),
                   hoverinfo='text',
                   text=[x[0] for x in allTraces[i]]
                   ))
            # Define the axis properties
            axis=dict(showbackground=False,
                showline=False, # hide axis line, grid, ticklabels and  title
                zeroline=False,
                showgrid=False,
                showticklabels=False,
                visible=False,
                title=''
                )
            # Define the figure's layout
            layout=Layout(title=figTitle,
                width=figSize[0],
                height=figSize[1],
                font= Font(size=12),
                showlegend=True,
                scene=Scene(
                    xaxis=XAxis(axis),
                    yaxis=YAxis(axis),
                    zaxis=ZAxis(axis)
                ),
                margin=Margin(
                    t=100,
                ),
                hovermode='closest',
                annotations=Annotations([
                    Annotation(
                    showarrow=False,
                    text=figTitle,
                    xref='paper',
                    yref='paper',
                    x=0,
                    y=0.1,
                    xanchor='left',
                    yanchor='bottom',
                    font=Font(
                        size=14
                        )
                    )
                    ]),
                )
            # Generate graph file
            data=Data(allScatters)
            fig=Figure(data=data, layout=layout)
            plot(fig, filename=figTitle.lower().replace(' ', '_'))
   

    except Exception as e:
        prettyPrintError(e)
        return False

    return True



