using Data;
using System.Linq;
using System.Windows.Threading;
using Tera.Game;

namespace DamageMeter.UI
{
    public class AbnormalityVM : TSPropertyChanged
    {
        private int _abnormalityId;
        private int _stacks;
        private bool _isCategory;
        private HotDot.Types _category;

        public int AbnormalityId
        {
            get => _abnormalityId;
            set
            {
                if (_abnormalityId == value) return;
                _abnormalityId = value;
                NotifyPropertyChanged();
                NotifyDisplayChanged();
            }
        }

        public int Stacks
        {
            get => _stacks;
            set
            {
                if (_stacks == value) return;
                _stacks = value;
                NotifyPropertyChanged();
                NotifyDisplayChanged();
            }
        }

        public bool IsCategory
        {
            get => _isCategory;
            set
            {
                if (_isCategory == value) return;
                _isCategory = value;
                NotifyPropertyChanged();
                NotifyDisplayChanged();
            }
        }

        public HotDot.Types Category
        {
            get => _category;
            set
            {
                if (_category == value) return;
                _category = value;
                NotifyPropertyChanged();
                NotifyDisplayChanged();
            }
        }

        public string DisplayName
        {
            get
            {
                if (IsCategory) { return $"Category: {Category}"; }

                var hotDot = BasicTeraData.Instance.HotDotDatabase?.Get(AbnormalityId);
                return string.IsNullOrWhiteSpace(hotDot?.Name)
                    ? $"Unknown abnormality ({AbnormalityId})"
                    : $"{hotDot.Name} ({AbnormalityId})";
            }
        }

        public string DetailsText
        {
            get
            {
                if (IsCategory) { return $"Category trigger: {Category}"; }

                var hotDot = BasicTeraData.Instance.HotDotDatabase?.Get(AbnormalityId);
                var stackText = Stacks > 0 ? $"Stack: {Stacks}" : "Any stack";
                if (hotDot == null)
                {
                    return $"ID: {AbnormalityId}\n{stackText}\nNot found in the current abnormality database.";
                }

                var effects = string.Join(", ", hotDot.Effects.Select(e => e.Type.ToString()));
                var tooltip = string.IsNullOrWhiteSpace(hotDot.Tooltip) ? "" : $"\n{hotDot.Tooltip}";
                return $"ID: {AbnormalityId}\n{stackText}\nType: {hotDot.AbType}\nEffects: {effects}{tooltip}";
            }
        }

        public AbnormalityVM(int id, int stacks) : base(Dispatcher.CurrentDispatcher)
        {
            IsCategory = false;
            _abnormalityId = id;
            _stacks = stacks;
        }

        public AbnormalityVM(HotDot.Types category) : base(Dispatcher.CurrentDispatcher)
        {
            IsCategory = true;
            Category = category;
        }

        private void NotifyDisplayChanged()
        {
            NotifyPropertyChanged(nameof(DisplayName));
            NotifyPropertyChanged(nameof(DetailsText));
        }
    }
}
