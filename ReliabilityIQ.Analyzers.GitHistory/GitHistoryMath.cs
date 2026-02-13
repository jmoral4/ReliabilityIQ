namespace ReliabilityIQ.Analyzers.GitHistory;

public static class GitHistoryMath
{
    public static double ComputeGiniCoefficient(IReadOnlyCollection<int> values)
    {
        if (values.Count == 0)
        {
            return 0d;
        }

        var ordered = values.Where(v => v > 0).OrderBy(v => v).Select(v => (double)v).ToArray();
        if (ordered.Length == 0)
        {
            return 0d;
        }

        if (ordered.Length == 1)
        {
            return 1d;
        }

        var n = ordered.Length;
        var sum = ordered.Sum();
        if (sum <= 0d)
        {
            return 0d;
        }

        double weighted = 0d;
        for (var i = 0; i < n; i++)
        {
            weighted += (i + 1) * ordered[i];
        }

        var gini = (2d * weighted) / (n * sum) - ((double)(n + 1) / n);
        return Math.Clamp(gini, 0d, 1d);
    }

    public static double ComputeChurnScore(int totalCommits, int linesAdded, int linesDeleted)
    {
        var totalLines = Math.Max(0, linesAdded) + Math.Max(0, linesDeleted);
        return Math.Max(0, totalCommits) * Math.Log(totalLines + 1d);
    }

    public static double ComputeStaleScore(int daysSinceLastCommit)
    {
        var safeDays = Math.Max(0, daysSinceLastCommit);
        return 1d - Math.Exp(-safeDays / 180d);
    }

    public static double Percentile(IReadOnlyList<double> values, double percentile)
    {
        if (values.Count == 0)
        {
            return 0d;
        }

        var sorted = values.OrderBy(v => v).ToArray();
        var rank = Math.Clamp(percentile, 0d, 1d) * (sorted.Length - 1);
        var lower = (int)Math.Floor(rank);
        var upper = (int)Math.Ceiling(rank);
        if (lower == upper)
        {
            return sorted[lower];
        }

        var weight = rank - lower;
        return sorted[lower] + (sorted[upper] - sorted[lower]) * weight;
    }
}
