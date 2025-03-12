# # ## Reads the CSV and generate visualisations (packet flow and protocol distribution) in visuals
''' 
Visualization Priority:
1.	Packet Flow + Alerts Timeline (High priority, immediate insights)
2.	Top Offending IP Addresses
3.	Alert Type Distribution
4.	Protocol Usage & Suspicious Activity
5.	Communication Network (Graph)
6.	Suspicious Activity Heatmap
'''

##DEBUG
# import pandas as pd

# def check_csv_structure(csv_file, name):
#     try:
#         df = pd.read_csv(csv_file, encoding="utf-8")
#         print(f"{name}: Loaded successfully with {df.shape[1]} columns")
#     except pd.errors.ParserError as e:
#         print(f"{name}: Error reading file - {e}")

import os
import sys
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import networkx as nx

def safe_read_csv(file_path):
    """Reads a CSV file safely, handling encoding issues and skipping bad lines."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        return pd.read_csv(file, engine="python", on_bad_lines="skip", dtype=str)

def clean_dataframe(df, is_detector=False):
    """Cleans a dataframe by converting columns to correct data types and handling NaN values."""
    df["time"] = pd.to_datetime(df["time"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
    df["length"] = pd.to_numeric(df["length"], errors="coerce")
    df["sport"] = pd.to_numeric(df["sport"], errors="coerce")
    df["dport"] = pd.to_numeric(df["dport"], errors="coerce")

    if is_detector and "suspicious_payload" in df.columns:
        df["suspicious_payload"] = df["suspicious_payload"].astype(str).str.lower() == "true"

    df = df.dropna(subset=["time", "length"])
    return df

def save_bar_chart(x, y, title, xlabel, ylabel, output_path, palette="Blues_r", rotate_xticks=False, legend_label=None):
    """Helper function to create and save a bar chart with a legend."""
    plt.figure(figsize=(12, 6))
    ax = sns.barplot(x=x, y=y, hue=x, palette=palette)

    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(axis="y", linestyle="--", linewidth=0.5)

    if rotate_xticks:
        plt.xticks(rotation=45)

    # Add legend if provided
    if legend_label:
        plt.legend([legend_label], loc="best")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"- \033[1m{title}\033[0m saved to {output_path}")

# Phase 1: Packet Flow + Alerts Timeline
def visualise_packet_flow(analyser_df, detector_df, output_folder):
    """Generates a time-series visualization of normal and suspicious traffic."""
    plt.figure(figsize=(14, 7))
    sns.lineplot(data=analyser_df, x="time", y="length", label="Normal Traffic", linewidth=1.5, alpha=0.7)
    sns.scatterplot(data=detector_df, x="time", y="length", color='red', marker='x', s=50, label="Suspicious Traffic")
    plt.xlabel("Time")
    plt.ylabel("Packet Size (Bytes)")
    plt.title("Packet Flow with Suspicious Traffic Highlights")
    plt.grid(True, linestyle="--", linewidth=0.5)
    plt.legend(loc="best")
    plt.xticks(rotation=45)
    plt.tight_layout()

    packet_flow_alerts_path = os.path.join(output_folder, "packet_flow_with_alerts.png")
    plt.savefig(packet_flow_alerts_path, dpi=300)
    plt.close()
    print(f"- \033[1mPacket Flow visualization\033[0m] saved to {packet_flow_alerts_path}")

# Phase 2: Top Offending IPs
def visualise_top_offending_ips(detector_df, output_folder, top_n=10):
    """Generates a bar chart of the top N most frequent offending IP addresses."""
    top_offenders = detector_df["source"].value_counts().nlargest(top_n)

    if top_offenders.empty:
        print("\n\033[1;33mWarning:\033[0m No top offending IPs found. Skipping visualization.")
        return

    save_bar_chart(
        top_offenders.index, top_offenders.values, f"Top {top_n} Offending IP Addresses",
        "Number of Suspicious Events", "IP Address",
        os.path.join(output_folder, "top_offending_ips.png"), "Reds_r",
        legend_label="Offending IPs"
    )

# Phase 3: Alert Type Distribution
def visualise_alert_type_distribution(detector_df, output_folder):
    """Generates a pie chart and a bar chart showing the distribution of alert types."""
    if "suspicious_reason" not in detector_df.columns:
        print("\n\033[1;33mWarning:\033[0m No 'suspicious_reason' column found. Skipping Alert Type Distribution.")
        return

    alert_counts = detector_df["suspicious_reason"].value_counts()
    if alert_counts.empty:
        print("\n\033[1;33mWarning:\033[0m No alert types found. Skipping Alert Type Distribution.")
        return

    plt.figure(figsize=(8, 8))
    plt.pie(alert_counts, labels=alert_counts.index, autopct="%1.1f%%", startangle=140, colors=sns.color_palette("Set3"))
    plt.title("Alert Type Distribution (Percentage)")
    plt.legend(title="Alert Types", loc="best")
    plt.tight_layout()
    pie_chart_path = os.path.join(output_folder, "alert_type_distribution_pie.png")
    plt.savefig(pie_chart_path, dpi=300)
    plt.close()
    print(f"- \033[1mAlert Type Distribution Pie Chart\033[0m saved to {pie_chart_path}")

    save_bar_chart(
        alert_counts.index, alert_counts.values, "Alert Type Distribution (Absolute Count)",
        "Alert Type", "Number of Alerts",
        os.path.join(output_folder, "alert_type_distribution_bar.png"), "Blues_r",
        rotate_xticks=True, legend_label="Alert Types"
    )

# Phase 4: Protocol Usage & Suspicious Activity
def visualise_protocol_usage(analyser_df, detector_df, output_folder):
    """Generates bar charts showing protocol usage in normal and suspicious activity."""
    protocol_counts_normal = analyser_df["protocol"].value_counts()
    protocol_counts_suspicious = detector_df["protocol"].value_counts()

    if protocol_counts_normal.empty and protocol_counts_suspicious.empty:
        print("\n\033[1;33mWarning\033[0m: No protocol data found. Skipping Protocol Usage visualization.")
        return

    if not protocol_counts_normal.empty:
        save_bar_chart(
            protocol_counts_normal.index, protocol_counts_normal.values, "Overall Protocol Distribution (Normal Traffic)",
            "Protocol", "Number of Packets",
            os.path.join(output_folder, "protocol_usage_normal.png"), "coolwarm",
            rotate_xticks=True, legend_label="Normal Traffic"
        )

    if not protocol_counts_suspicious.empty:
        save_bar_chart(
            protocol_counts_suspicious.index, protocol_counts_suspicious.values, "Suspicious Protocol Distribution (Alerted Traffic)",
            "Protocol", "Number of Alerts",
            os.path.join(output_folder, "protocol_usage_suspicious.png"), "Reds_r",
            rotate_xticks=True, legend_label="Suspicious Traffic"
        )

# Phase 5: Communication Network Graph
def visualise_communication_network(analyser_df, detector_df, output_folder):
    """ Generates a communication network graph with total nodes count in title and legend. """
    G = nx.DiGraph()

    # Extract normal and suspicious edges
    normal_edges = list(zip(analyser_df["source"], analyser_df["destination"]))
    suspicious_edges = list(zip(detector_df["source"], detector_df["destination"]))

    for src, dst in normal_edges:
        if pd.notna(src) and pd.notna(dst):
            G.add_edge(src, dst, color="blue", weight=0.5)  # Normal traffic

    for src, dst in suspicious_edges:
        if pd.notna(src) and pd.notna(dst):
            G.add_edge(src, dst, color="red", weight=2.0)  # Suspicious traffic

    # Define total node count
    total_nodes = len(G.nodes())

    # Generate layout
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, k=0.5, seed=42)  # Spacing adjustment
    edge_colors = [G[u][v]["color"] for u, v in G.edges()]
    edge_weights = [G[u][v]["weight"] for u, v in G.edges()]
    node_sizes = [G.degree(n) * 100 for n in G.nodes()]

    nx.draw(G, pos, with_labels=False, node_size=node_sizes, edge_color=edge_colors, width=edge_weights, alpha=0.7, arrows=True)

    # Add labels for important nodes
    important_nodes = [n for n in G.nodes() if G.degree(n) > 3]
    labels = {n: n if n in important_nodes else "" for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)

    # Update title with total nodes
    plt.title(f"Communication Network\nTotal Nodes: {total_nodes}", fontsize=14, fontweight="bold")

    # Update legend with total nodes count
    legend_labels = [
        plt.Line2D([0], [0], color="blue", lw=2, label="Normal Traffic"),
        plt.Line2D([0], [0], color="red", lw=2, label="Suspicious Traffic"),
        plt.Line2D([0], [0], color="purple", lw=2, label="Mixed Traffic (Normal & Suspicious)"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="black", markersize=8, label=f"Total Nodes: {total_nodes}")
    ]
    plt.legend(handles=legend_labels, loc="upper right")
    plt.margins(0.1)

    # Save graph
    network_graph_path = os.path.join(output_folder, "communication_network.png")
    plt.savefig(network_graph_path, dpi=300)
    plt.close()
    print(f"- \033[1mCommunication Network Graph\033[0m saved to {network_graph_path}")

# Phase 6: Suspicious Activity Heatmap
def visualise_suspicious_activity_heatmap(detector_df, output_folder):
    """ Generates a heatmap showing the intensity of suspicious activity over time. """
    detector_df["time"] = pd.to_datetime(detector_df["time"], errors="coerce")
    detector_df["time"] = detector_df["time"].dt.floor("min")  # Group by minute

    heatmap_data = detector_df.groupby(["time", "suspicious_reason"]).size().unstack(fill_value=0)

    if heatmap_data.empty:
        print("\n\033[1;33mWarning:\033[0m No data for heatmap. Skipping visualization.")
        return

    plt.figure(figsize=(12, 6))
    sns.heatmap(heatmap_data.T, cmap="Reds", linewidths=0.5, linecolor="gray", annot=True, fmt="d")
    plt.xlabel("Time")
    plt.ylabel("Alert Type")
    plt.title("Suspicious Activity Heatmap (Alerts Over Time)")
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save heatmap
    heatmap_path = os.path.join(output_folder, "suspicious_activity_heatmap.png")
    plt.savefig(heatmap_path, dpi=300)
    plt.close()
    print(f"- \033[1mSuspicious Activity Heatmap\033[0m saved to {heatmap_path}")

# Main Execution
def main():
    analyser_csv = sys.argv[1]
    detector_csv = sys.argv[2]
    output_folder= sys.argv[3]
    
    os.makedirs(output_folder, exist_ok=True)
    
    print(f"\nVisualizations will be saved to: {output_folder}")
    
    # Read CSVs
    analyser_df = safe_read_csv(analyser_csv)
    detector_df = safe_read_csv(detector_csv)
    
    # Ensure the CSVs exist before proceeding
    if analyser_df is None or detector_df is None:
        print("\n\033[1;31mERROR:\33[0m Missing required CSV files. Exiting.")
        return

    # Ensure necessary columns exist before cleaning
    required_columns = ["time", "length", "source", "destination"]
    for col in required_columns:
        if col not in analyser_df.columns:
            analyser_df[col] = "Unknown" if col in ["source", "destination"] else 0
        if col not in detector_df.columns:
            detector_df[col] = "Unknown" if col in ["source", "destination"] else 0

    # Convert time column properly
    # Explicitly define the expected datetime format (to allow adjustment if required)
    expected_format = "%Y-%m-%d %H:%M:%S" 

    analyser_df["time"] = pd.to_datetime(analyser_df["time"], format=expected_format, errors="coerce")
    detector_df["time"] = pd.to_datetime(detector_df["time"], format=expected_format, errors="coerce")

    # Drop rows with missing timestamps
    analyser_df.dropna(subset=["time"], inplace=True)
    detector_df.dropna(subset=["time"], inplace=True)

    # Clean the DataFrames
    analyser_df = clean_dataframe(analyser_df)
    detector_df = clean_dataframe(detector_df, is_detector=True)

    # Ensure sorting happens after cleaning and valid timestamps
    if not analyser_df.empty:
        analyser_df.sort_values("time", inplace=True)
    if not detector_df.empty:
        detector_df.sort_values("time", inplace=True)
    

    # Execute all visualization phases
    visualise_packet_flow(analyser_df, detector_df, output_folder)
    visualise_top_offending_ips(detector_df, output_folder)
    visualise_alert_type_distribution(detector_df, output_folder)
    visualise_protocol_usage(analyser_df, detector_df, output_folder)
    visualise_communication_network(analyser_df, detector_df, output_folder)
    visualise_suspicious_activity_heatmap(detector_df, output_folder) 
      
    print(f"\nVisualiser output saved in {output_folder}")

if __name__ == "__main__":
    main()