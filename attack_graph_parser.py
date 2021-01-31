#!/usr/bin/env python
"""Module responsible for generating the attack graph."""

from queue import Queue
import time
import networkx as nx

from components import reader
from components import topology_parser as top_par

import ctypes
import pathlib

def clean_vulnerabilities(raw_vulnerabilities, container):
    """Cleans the vulnerabilities for a given container."""

    vulnerabilities = {}

    # Going to the .json hierarchy to get the CVE ids.
    layers = raw_vulnerabilities["Layers"]
    for layer in layers:
        features = layer["Layer"]["Features"]
        for feature in features:
            if "Vulnerabilities" not in feature:
                continue

            vulnerabilities_structure = feature["Vulnerabilities"]
            for vulnerability in vulnerabilities_structure:
                vulnerability_new = {}

                # Finding the description
                if "Description" in vulnerability.keys():
                    vulnerability_new["desc"] = vulnerability["Description"]
                else:
                    vulnerability_new["desc"] = "?"

                # Finding the attack vector
                vulnerability_new["attack_vec"] = "?"
                if "Metadata" in vulnerability.keys():
                    metadata = vulnerability["Metadata"]
                    if "NVD" not in metadata:
                        continue

                    if "CVSSv2" not in metadata["NVD"]:
                        continue

                    if "Vectors" in metadata["NVD"]["CVSSv2"]:
                        vec = metadata["NVD"]["CVSSv2"]["Vectors"]
                        vulnerability_new["attack_vec"] = vec
                vulnerabilities[vulnerability["Name"]] = vulnerability_new

    print("Total " + str(len(vulnerabilities))
          + " vulnerabilities in container "+container+".")

    return vulnerabilities

def get_graph(attack_paths):
    """Getting the nodes and edges for an array of attack paths."""

    # Initializing the nodes and edges arrays.
    nodes = []
    edges = {}

    # Generating unique nodes.
    for attack_path in attack_paths:
        for node in attack_path:
            if node not in nodes:
                nodes.append(node)

    # Generating unique edges.
    for attack_path in attack_paths:

        # Checking if an edge is present.
        if len(attack_path) >= 2:
            for i in range(1, len(attack_path)):
                key = attack_path[i]+"|"+attack_path[i-1]
                edges[key] = [attack_path[i], attack_path[i-1]]

    return nodes, edges

def get_attack_vector(attack_vector_files):
    """Merging the attack vector files into a dictionary."""

    # Initializing the attack vector dictionary.
    attack_vector_dict = {}

    count = 0
    # Iterating through the attack vector files.
    for attack_vector_file in attack_vector_files:

        # Load the attack vector.
        cve_items = attack_vector_file["CVE_Items"]

        # Filtering only the important information and creating the dictionary.
        for cve_item in cve_items:
            dictionary_cve = {}
            dictionary_cve["attack_vec"] = "?"
            dictionary_cve["desc"] = "?"
            dictionary_cve["cpe"] = "?"

            # Getting the attack vector and the description.
            if "baseMetricV2" in cve_item["impact"]:

                cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]

                cve_attack_vector = cve_item["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]
                dictionary_cve["attack_vec"] = cve_attack_vector

                if "description" in cve_item["cve"]:

                    descr = cve_item["cve"]["description"]["description_data"][0]['value']
                    dictionary_cve["desc"] = descr

            # Get the CPE values: a - application, o - operating system and h - hardware
            nodes = cve_item["configurations"]["nodes"]
            if len(nodes) > 0:
                if "cpe" in nodes[0]:
                    cpe = cve_item["configurations"]["nodes"][0]["cpe"][0]["cpe22Uri"]
                    dictionary_cve["cpe"] = cpe
                    count = count + 1
                else:
                    if "children" in nodes[0] and "cpe" in nodes[0]["children"][0]:
                        cpe = nodes[0]["children"][0]["cpe"][0]["cpe22Uri"]
                        dictionary_cve["cpe"] = cpe
                        count = count + 1

            if dictionary_cve["cpe"] != "?":
                dictionary_cve["cpe"] = dictionary_cve["cpe"][5]
            attack_vector_dict[cve_id] = dictionary_cve
    return attack_vector_dict

def add_edge(nodes,
             edges,
             node_start,
             node_start_priv,
             node_end,
             node_end_priv,
             edge_desc,
             passed_edges):
    """Adding an edge to the attack graph and checking if nodes already exist."""

    
    """for key in edges.keys():
        if key.endswith(node_start):
            container = node_end.split("(")[0]
            if key.startswith(container):
                return nodes, edges, passed_edges"""

    # Checks if the opposite edge is already in the collection. If it is, dont add the edge.
    node_start_full = node_start + "(" + node_start_priv + ")"
    node_end_full = node_end+ "(" + node_end_priv + ")"

    node = passed_edges.get(node_end + "|" + node_start_full)
    if node == None:
        passed_edges[ node_start + "|" + node_end_full ] = True
    else:
        return nodes, edges, passed_edges

    if node_start_full not in nodes:
        nodes.add(node_start_full)

    if node_end not in nodes:
        nodes.add(node_end_full)

    key = node_start_full + "|" + node_end_full 

    edge = edges.get(key)
    if edge == None:
        edges[key] = [edge_desc]
    else:
        edge.append(edge_desc)
        edges[key] = edge

    return nodes, edges, passed_edges

def breadth_first_search(topology,
                         container_exploitability,
                         priviledged_access):
    """Breadth first search approach for generation of nodes and edges
    without generating attack paths."""
    c_start = time.time()
    #########################################################
    # encoding all containers
    container_encoding = {} #map container name to encoding number
    container_decoding = {} #map encoding number to container name
    cont_cnt = 0 ################# pass to c function: number of containers
    for i in topology.keys():
        container_encoding[i]=cont_cnt
        container_decoding[cont_cnt]=i
        cont_cnt += 1

    outside_id = container_encoding['outside'] ################ pass to c function
    docker_host_id = container_encoding['docker host'] ################ pass to c function

    # build topology matrix as 1D array
    topology_list = [0 for i in range(cont_cnt**2)] ################ pass to c function: topology matrix

    for i in topology.keys():
        for j in topology[i]:
            topology_list[container_encoding[i]*cont_cnt+container_encoding[j]]=1
        # add reflective edges. 
        # The original python program forgot to delete these edges after graph is generated
        if i!= "docker host" and i!= "outside":
            topology[i].append(i)
            topology[i].append(i)
    
    # encoding all exploits
    exploit_encoding = {}
    exploit_decoding = {}
    num_ex = [0 for i in range(cont_cnt)] ################ pass to c function: number of exploits of each container
    max_num_ex = 0 ################# pass to c function: max number of exploits of all containers
    ex_cnt = 0
    ex_total = 0
    for i in container_exploitability.keys():
        ex_cnt = len(container_exploitability[i]['precond'].keys())
        num_ex[container_encoding[i]]=ex_cnt
        if ex_cnt>max_num_ex: max_num_ex=ex_cnt
        for j in container_exploitability[i]['precond'].keys():
            if j not in exploit_encoding:
                exploit_encoding[j]=ex_total
                exploit_decoding[ex_total]=j
                ex_total += 1
   
    # build precondition name matrix as 1D array, size cont_cnt * max_num_ex
    ex_names = [-1 for i in range(cont_cnt * max_num_ex)] ############### pass to c function: initially -1 means an empty entry
    pre_priv = [0 for i in range(cont_cnt * max_num_ex)] ############## pass to c function: initially 0 means None privilege
    post_priv = [0 for i in range(cont_cnt * max_num_ex)] ############## pass to c function: initially 0 means None privilege
    for i in container_exploitability.keys():
        ex_cnt = 0
        for j in container_exploitability[i]['precond'].keys():
            ex_names[container_encoding[i]*max_num_ex + ex_cnt]=exploit_encoding[j]
            pre_priv[container_encoding[i]*max_num_ex + ex_cnt]=container_exploitability[i]['precond'][j]
            post_priv[container_encoding[i]*max_num_ex + ex_cnt]=container_exploitability[i]['postcond'][j]
            ex_cnt += 1

    # build previlege access list
    pacc_list = [0 for i in range(cont_cnt)] ############### pass to c function: priviledged access
    for i in priviledged_access.keys():
        pacc_list[container_encoding[i]] = 1 if priviledged_access[i] else 0

    ####################################################################  
    
    libname = pathlib.Path().absolute()/"c_bfs.so"
    bfs = ctypes.CDLL(libname).bfs
    IntArrayTopo = ctypes.c_int*(cont_cnt**2)
    IntArrayCont = ctypes.c_int*cont_cnt
    IntArrayEx = ctypes.c_int*(cont_cnt*max_num_ex)
    
    param_topology_list = IntArrayTopo(*topology_list)
    param_num_ex_list = IntArrayCont(*num_ex)
    param_ex_names_list = IntArrayEx(*ex_names)
    param_pre_priv_list = IntArrayEx(*pre_priv)
    param_post_priv_list = IntArrayEx(*post_priv)
    param_pacc_list = IntArrayCont(*pacc_list)
    param_cont_cnt = cont_cnt
    param_outside_name = outside_id
    param_docker_host_name = docker_host_id
    param_max_num_ex = max_num_ex

    nodeLimit = 10000
    edgeLimit = 2500000
    labelPerNode = 100

    # Set result type as int list
    # The result stores the exploit labels on each edge
    bfs.restype = ctypes.POINTER(ctypes.c_int*(edgeLimit*labelPerNode))

    IntArrayOne = ctypes.c_uint*1
    IntArrayNode = ctypes.c_uint*nodeLimit
    IntArrayEdge = ctypes.c_uint*edgeLimit

    nodeCnt = IntArrayOne(*[0])
    edgeCnt = IntArrayOne(*[0])
    nodeName = IntArrayNode(*[0 for i in range(nodeLimit)])
    nodePriv = IntArrayNode(*[0 for i in range(nodeLimit)])
    edgeStart = IntArrayEdge(*[0 for i in range(edgeLimit)])
    edgeEnd = IntArrayEdge(*[0 for i in range(edgeLimit)])
    
    numOpenmpThreads = 4
    initQueueSize = 4

    res = bfs(param_topology_list, param_num_ex_list, param_ex_names_list, param_pre_priv_list, param_post_priv_list, param_pacc_list, param_cont_cnt, param_outside_name, param_docker_host_name, param_max_num_ex, nodeName, nodePriv, edgeStart, edgeEnd, nodeCnt, edgeCnt, numOpenmpThreads, initQueueSize)

    nodes = set()
    edges = {}

    priv_dict = {0: "NONE",
               1 : "VOS USER",
               2 : "VOS ADMIN",
               3: "USER",
               4: "ADMIN"}    

    # make the nodes set with the results of c_bfs
    for i in range(nodeCnt[0]):
        nodes.add(container_decoding[nodeName[i]]+"("+priv_dict[nodePriv[i]]+")")

    # make the edges dictionary with the results of c_bfs
        
    for i in range(edgeCnt[0]):
        start_id = edgeStart[i]
        end_id = edgeEnd[i]
        start_name = container_decoding[nodeName[start_id]]
        end_name = container_decoding[nodeName[end_id]]
        start_priv = priv_dict[nodePriv[start_id]]
        end_priv = priv_dict[nodePriv[end_id]]
        edge_key = start_name + "(" + start_priv + ")|" + end_name + "(" + end_priv + ")"
        edges[edge_key] = []
        labelTotal = res.contents[i*100]
        labelStartAddress = i*100+1
        for j in range(labelTotal):
            exploit_value = res.contents[labelStartAddress+j]
            if exploit_value==-1: edges[edge_key].append("root access")
            elif exploit_value==-2: edges[edge_key].append("privileged")
            else: edges[edge_key].append(exploit_decoding[exploit_value]) 

    c_duration=time.time()-c_start
    print("====== Report From Python ======") 
    print("C-based parallel BFS done!!!")
    print("Number of nodes in the attack graph is", len(nodes))
    print("Number of edges in the attack graph is", len(edges))
    print("Parallel BFS took",c_duration,"seconds")
    print()
    return nodes, edges, c_duration

def attack_vector_string_to_dict(av_string):
    """Transforms the attack vector string to dictionary."""

    av_dict = {}

    # Remove brackets.
    if av_string[0] == "(":
        av_string = av_string[1:len(av_string)-1]

    # Put structure into dictionary
    categories = av_string.split("/")
    for category in categories:
        parts = category.split(":")
        av_dict[parts[0]] = parts[1]

    return av_dict

def merge_attack_vector_vuls(attack_vector_dict, vulnerabilities):
    """Merging the information from vulnerabilities and the attack vector files."""

    merged_vulnerabilities = {}

    for vulnerability in vulnerabilities:
        vulnerability_new = {}
        if vulnerability in attack_vector_dict:

            vulnerability_new["desc"] = attack_vector_dict[vulnerability]["desc"]

            if attack_vector_dict[vulnerability]["attack_vec"] != "?":
                av_string = attack_vector_dict[vulnerability]["attack_vec"]
                attack_vec = attack_vector_string_to_dict(av_string)
                vulnerability_new["attack_vec"] = attack_vec
            vulnerability_new["cpe"] = attack_vector_dict[vulnerability]["cpe"]

        else:

            vulnerability_new["desc"] = vulnerabilities[vulnerability]["desc"]
            if vulnerabilities[vulnerability]["attack_vec"] != "?":

                av_string = vulnerabilities[vulnerability]["attack_vec"]
                attack_vec = attack_vector_string_to_dict(av_string)
                vulnerability_new["attack_vec"] = attack_vec

            vulnerability_new["cpe"] = "?"

        merged_vulnerabilities[vulnerability] = vulnerability_new

    return merged_vulnerabilities

def get_val(privilege):
    """Mapping the privilege level to its value, so that it can be compared later."""

    mapping = {"NONE": 0,
               "VOS USER" : 1,
               "VOS ADMIN" : 2,
               "USER": 3,
               "ADMIN": 4}

    return mapping[privilege]

def get_priv(privilege):
    """Mapping the value to the privilege level for easier readability in the attack graph."""

    mapping = {0: "NONE",
               1 : "VOS USER",
               2 : "VOS ADMIN",
               3: "USER",
               4: "ADMIN"}

    return mapping[privilege]

def get_rule_precondition(rule, vul, precond, vul_key):
    """Checks if it finds rule precondition"""

    # Checks if the cpe in the rule is same with vulnerability.
    if rule["cpe"] != "?":
        if rule["cpe"] == "o" and vul["cpe"] != "o":
            return precond
        elif rule["cpe"] == "h" and (vul["cpe"] != "h" and vul["cpe"] != "a"):
            return precond

    # Checks if the vocabulary is matching
    if "vocabulary" in rule.keys():
        sentences = rule["vocabulary"]
        hit_vocab = False
        for sentence in sentences:
            if "..." in sentence:
                parts = sentence.split("...")
                if parts[0] in vul["desc"] and parts[1] in vul["desc"]:
                    hit_vocab = True
                    break
            elif "?" == sentence:
                hit_vocab = True
                break
            elif sentence in vul["desc"]:
                hit_vocab = True
                break
        if hit_vocab and \
           (vul_key not in precond or precond[vul_key] < get_val(rule["precondition"])):
            precond[vul_key] = get_val(rule["precondition"])

    # Check access vector
    else:
        if rule["accessVector"] != "?":

            if rule["accessVector"] == "LOCAL" and vul["attack_vec"]["AV"] != "L":
                return precond
            elif vul["attack_vec"]["AV"] != "A" and vul["attack_vec"]["AV"] != "N":
                return precond

        if rule["authentication"] != "?":
            if rule["authentication"] == "NONE" and vul["attack_vec"]["Au"] != "N":
                return precond
            elif vul["attack_vec"]["Au"] != "L" and vul["attack_vec"]["Au"] != "H":
                return precond

        if rule["accessComplexity"][0] == vul["attack_vec"]["AC"] and \
        (vul_key not in precond or precond[vul_key] < get_val(rule["precondition"])):
            precond[vul_key] = get_val(rule["precondition"])

    return precond

def get_rule_postcondition(rule, vul, postcond, vul_key):
    """Checks if it finds rule postcondition"""

    # Checks if the cpe in the rule is same with vulnerability.
    if rule["cpe"] != "?":
        if rule["cpe"] == "o" and vul["cpe"] != "o":
            return postcond
        elif rule["cpe"] == "h" and (vul["cpe"] != "h" and vul["cpe"] != "a"):
            return postcond

    # Checks if the vocabulary is matching
    sentences = rule["vocabulary"]
    hit_vocab = False
    for sentence in sentences:
        if "..." in sentence:
            parts = sentence.split("...")
            if parts[0] in vul["desc"] and parts[1] in vul["desc"]:
                hit_vocab = True
                break
        elif "?" == sentence:
            hit_vocab = True
            break
        elif sentence in vul["desc"]:
            hit_vocab = True
            break
    if not hit_vocab:
        return postcond

    # Check Impacts
    if rule["impacts"] == "ALL_COMPLETE":
        if vul["attack_vec"]["I"] == "C" and vul["attack_vec"]["C"] == "C":
            if vul_key not in postcond or postcond[vul_key] > get_val(rule["postcondition"]):
                postcond[vul_key] = get_val(rule["postcondition"])

    elif rule["impacts"] == "PARTIAL":

        if vul["attack_vec"]["I"] == "P" or vul["attack_vec"]["C"] == "P":
            if vul_key not in postcond or postcond[vul_key] > get_val(rule["postcondition"]):
                postcond[vul_key] = get_val(rule["postcondition"])

        else:
            if vul_key not in postcond or postcond[vul_key] > get_val(rule["postcondition"]):
                postcond[vul_key] = get_val(rule["postcondition"])

    elif rule["impacts"] == "ANY_NONE":
        if vul["attack_vec"]["I"] == "N" or vul["attack_vec"]["C"] == "N":
            if vul_key not in postcond or postcond[vul_key] > get_val(rule["postcondition"]):
                postcond[vul_key] = get_val(rule["postcondition"])

    return postcond

def rule_processing(merged_vul, pre_rules, post_rules):
    """ This functions is responspible for creating the
    precondition and postcondition rules."""

    precond = {}
    postcond = {}
    for vul_key in merged_vul:
        vul = merged_vul[vul_key]

        if "attack_vec" not in vul or vul["attack_vec"] == "?":
            continue
        for pre_rule in pre_rules:
            rule = pre_rules[pre_rule]
            precond = get_rule_precondition(rule, vul, precond, vul_key)

        for post_rule in post_rules:
            rule = post_rules[post_rule]
            postcond = get_rule_postcondition(rule, vul, postcond, vul_key)

        # Assign default values if rules are undefined
        if vul_key not in precond:
            precond[vul_key] = 0 # 0 is None level
        if vul_key not in postcond:
            postcond[vul_key] = 4 # 4 is Admin level

    return precond, postcond

def get_exploitable_vuls_container(vulnerabilities,
                                   container_name,
                                   attack_vector_dict,
                                   pre_rules,
                                   post_rules):
    """Processes and provides exploitable vulnerabilities per container."""

    # Remove junk and just takethe most important part from each vulnerability
    cleaned_vulnerabilities = clean_vulnerabilities(vulnerabilities, container_name)

    # Merging the cleaned vulnerabilities
    merged_vul = merge_attack_vector_vuls(attack_vector_dict, cleaned_vulnerabilities)

    # Get the preconditions and postconditions for each vulnerability.
    precond, postcond = rule_processing(merged_vul, pre_rules, post_rules)
    exploitability_dict = {"precond": precond, "postcond":postcond}

    return exploitability_dict

def generate_attack_graph(attack_vector_path,
                          pre_rules,
                          post_rules,
                          topology,
                          vulnerabilities,
                          example_folder):
    """Main pipeline for the attack graph generation algorithm."""

    print("Start with attack graph generation...")
    
    t_start = time.time()
    # Read the attack vector files.
    attack_vector_files = reader.read_attack_vector_files(attack_vector_path)
    print("Attack vector reading took", time.time()-t_start, "seconds");

    print("Vulnerabilities preprocessing started.")
    time_start = time.time()

    # Read the service to image mapping.
    mapping_names = top_par.get_mapping_service_to_image_names(example_folder)

    # Read priviledged containers from docker-compose.yml
    privileged_access = reader.check_priviledged_access(mapping_names, example_folder)

    # Merging the attack vector files and creating an attack vector dictionary.
    attack_vector_dict = get_attack_vector(attack_vector_files)

    # Getting the potentially exploitable vulnerabilities for each container.
    exploitable_vuls = {}
    for container in topology.keys():
        if container != "outside" and container != "docker host":

            # Reading the vulnerability
            exploitable_vuls[container] = get_exploitable_vuls_container(vulnerabilities[container],
                                                                         container,
                                                                         attack_vector_dict,
                                                                         pre_rules,
                                                                         post_rules)

    duration_vuls_preprocessing = time.time() - time_start
    print("Vulnerabilities preprocessing finished. Time elapsed: " + \
          str(duration_vuls_preprocessing) + \
          " seconds.\n")

    # Breadth first search algorithm for generation of attack paths.
    print("Breadth-first search started.")
    nodes, edges, duration_bdf = breadth_first_search(topology,
                                                      exploitable_vuls,
                                                      privileged_access)

    print("Breadth-first search finished. Time elapsed: "+str(duration_bdf)+" seconds.\n")

    # Returns a graph with nodes and edges.
    return nodes, edges, duration_bdf, duration_vuls_preprocessing

def print_graph_properties(label_edges, nodes, edges):
    """This functions prints graph properties."""

    print("\n**********Attack Graph properties**********")

    time_start = time.time()

    # Create the graph
    graph = nx.DiGraph()

    for node in nodes:
        graph.add_node(node)
    for edge_name in edges.keys():
        terminal_points = edge_name.split("|")

        edge_vuls = edges[edge_name]

        if label_edges == "single":
            for edge_vul in edge_vuls:
                graph.add_edge(terminal_points[0],
                               terminal_points[1],
                               contstraint='false')

        elif label_edges == "multiple":
            graph.add_edge(terminal_points[0],
                           terminal_points[1],
                           contstraint='false')

    # Calculate the attack graph properties

    # Number of nodes
    no_nodes = graph.number_of_nodes()
    print("The number of nodes in the graph is "+str(no_nodes)+"\n")

    # Number of edges
    no_edges = graph.number_of_edges()
    print("The number of edges in the graph is "+str(no_edges)+"\n")

    # Degree centrality
    degree_centrality = nx.degree_centrality(graph)
    print("The degree centrality of the graph is: ")
    for item in degree_centrality.keys():
        print(str(item)+" "+str(degree_centrality[item]))

    # Average degree centrality
    avg_degree_centrality = 0
    for node in degree_centrality:
        avg_degree_centrality = avg_degree_centrality + degree_centrality[node]
    if no_nodes != 0:
        avg_degree_centrality = avg_degree_centrality / no_nodes
    print("The average degree centrality of the graph is: "+str(avg_degree_centrality)+"\n")

    # In-degree and average in-degree
    in_degree = graph.in_degree()
    print("The in-degree is:")
    for item in in_degree:
        print(item)

    avg_in_degree = 0
    for node in in_degree:
        avg_in_degree = avg_in_degree + node[1]
    if no_nodes != 0:
        avg_in_degree = avg_in_degree / no_nodes
    print("The average in-degree is "+str(avg_in_degree))
    print("\n")

    out_degree = graph.out_degree()
    print("The out-degree is:")
    for item in out_degree:
        print(item)

    avg_out_degree = 0
    for node in out_degree:
        avg_out_degree = avg_out_degree + node[1]
    if no_nodes != 0:
        avg_out_degree = avg_out_degree / no_nodes
    print("The average out-degree is "+str(avg_out_degree))
    print("\n")

    if no_nodes != 0:
        print("Is the graph strongly connected? "+str(nx.is_strongly_connected(graph))+"\n")

    duration_graph_properties = time.time() - time_start
    print("Time elapsed: "+str(duration_graph_properties)+" seconds.\n")

    return duration_graph_properties
