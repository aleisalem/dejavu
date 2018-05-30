#!/usr/bin/python

from trout.utils.data import *
from trout.utils.graphics import *
from trout.utils.misc import *

import numpy as np
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA

import plotly.plotly as py
from plotly.offline import plot, iplot
from plotly.graph_objs import *


RGB = ["#ff4136", "#3d9970", "#ff851b", "#6baed6", "#808389", "#48494c"] # Normal colors

def reduceAndVisualize(X, y, dim=2, reductionAlgorithm="tsne", figSize=(1024,1024), figTitle="Data visualization", appNames=[], appTypes=[], saveProjectedData=False):
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
    :param saveProjectedData: Whether to save the projected data in a CSV file
    :type saveProjectedData: bool
    :return: A bool depicting the success/failure of the operaiton
    """
    try:
        # Prepare data
        X, y = np.array(X), np.array(y)
        # Build model
        reductionModel = TSNE(n_components=dim) if reductionAlgorithm == "tsne" else None
        # Apply transformation
        prettyPrint("Projecting %s feature vectors of dimensionality %s into %s-d" % (X.shape[0], X.shape[1], dim))
        X_new = reductionModel.fit_transform(X)
        # Generate a scatter plot
        prettyPrint("Populating the traces for malware and goodware")
        traceCount = max(y)+1
        appTypes = appTypes if len(appTypes) > 0 else ["Unknown"]*traceCount
        # Create traces for the scatter plot 
        prettyPrint("Creating a scatter plot")
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



